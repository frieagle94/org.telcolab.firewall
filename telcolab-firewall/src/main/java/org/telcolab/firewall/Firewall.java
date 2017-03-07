package org.telcolab.firewall;

import org.slf4j.Logger;
import static org.slf4j.LoggerFactory.getLogger;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.*;
import org.onosproject.net.flowobjective.*;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.*;
import org.onosproject.net.packet.*;
import org.onosproject.net.topology.TopologyService;

import java.util.*;

/**
 * Applicazione di forwarding e firewall che utilizza il servizio di intent.
 * @author Riccardo Frigerio
 */
 
@Component(immediate = true)
public class Firewall {
	
    // Nome applicazione
    private ApplicationId appId;
    
    // Log dell'applicazione
    private final Logger log = getLogger(getClass());

	// Variabili per accedere per ai servizi di ONOS
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected IntentService intentService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowObjectiveService flowObjectiveService;

    private static final int DROP_RULE_TIMEOUT = 300;

    private static final EnumSet<IntentState> WITHDRAWN_STATES = EnumSet.of(IntentState.WITHDRAWN,
                                                                            IntentState.WITHDRAWING,
                                                                            IntentState.WITHDRAW_REQ);

    private static final EnumSet<IntentState> CAN_PURGE = EnumSet.of(IntentState.WITHDRAWN, IntentState.FAILED);

    // Lista dei MAC degli host bloccati dal Firewall
    private ArrayList<MacAddress> blacklist = new ArrayList<MacAddress>();

    // Runnable custom per il monitor
    private MonitorRunnable monRun;
    // e sua implementazione
    private class MonitorRunnable implements Runnable {
	
		// OGGETTO MonitorHandler che gestisce il monitoraggio
		private MonitorHandler monitor = new MonitorHandler(log, deviceService, hostService);
	
		// Indica se interrompere il Runnable
		private boolean end = false;
	
		// Lista di oggetti Runnable custom per il firewall
		private ArrayList<FirewallRunnable> firewallRuns = new ArrayList<FirewallRunnable>();
		// e loro implementazione
		private class FirewallRunnable implements Runnable {

			// Indirizzo MAC da bannare
			private MacAddress mac;
	    
			// Costruttore del Runnable per il firewall
			public FirewallRunnable(MacAddress mac){
				this.mac = mac;
			}

			@Override
			public void run(){
			    try {
				drop(mac);
				Thread.sleep(MonitorHandler.BAN_TIME*1000);
				undrop(mac);
			    } catch (InterruptedException e) {}
			}
		}

		@Override
		public void run(){ 
			
			// Eseguo all'infinito fino al termine del programma
			while(!end) {

			    log.info("");
			    log.info("");
			
				// Eseguo il vero e proprio monitoraggio
				monitor.monitor();
			
				// Aggiorno il firewall dopo aver scoperto eventuali incriminati
				updateBan(monitor.getDoS());
			
				try {
					log.info("Console refresh in 3 seconds...");
					Thread.sleep(1000);
					Thread.sleep(1000);
					Thread.sleep(1000);
				} catch (InterruptedException e) {}
			}
		}
	

		// METODO che aggiorna la lista dei MAC bannati
		private void updateBan(ArrayList<MacAddress> update){
			for (MacAddress mac : update){
			
				// Se il MAC non e' gia' bloccato, ne creo un Runnable responsabile della gestione del ban
				if(!blacklist.contains(mac)){
				FirewallRunnable fireRun = new FirewallRunnable(mac);
				firewallRuns.add(fireRun);
				Thread fireThread = new Thread(fireRun);
				fireThread.start();
				}	    
			}
		}
	
		// METODO che rimuove il mac da sbloccare dalla lista nera del monitor
		public void unban(MacAddress mac){
			this.monitor.unban(mac);
		}
	
		// METODO per far terminare il thread
		public void setEnd(){
			this.end = true;
		}
	}

    // PacketProcessor custom
    private CustomPacketProcessor processor = new CustomPacketProcessor();
    // e sua implementzione
    private class CustomPacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            // Stop processing if the packet has been handled, since we
            // can't do any more to it.
            if (context.isHandled())
                return;

            InboundPacket packet = context.inPacket();
            Ethernet ethPacket = packet.parsed();

			// Se il pacchetto e' nullo lo scarto
            if (ethPacket == null)
                return;

			// altrimenti acquisisco gli host coinvolti nello scambio
            HostId srcId = HostId.hostId(ethPacket.getSourceMAC());
            HostId dstId = HostId.hostId(ethPacket.getDestinationMAC());

            // Se'l host di destinazione non e' gia conosciuto, effettuo il flood
            Host dst = hostService.getHost(dstId);
            if (dst == null) {
                flood(context);
                return;
            }

            // altrimenti, inoltro semplicemente il pacchetto
            setIntent(context, srcId, dstId);
            forward(context, dst);
        }
    }
    
    @Activate
    public void activate() {

		// Set nome applicazione
        appId = coreService.registerApplication("org.telcolab.firewall");
        
		// Aggiungo il mio PacketProcessor custom al servizio di gestione dei pacchetti
		packetService.addProcessor(processor, PacketProcessor.ADVISOR_MAX + 2);

		// Costruisco un oggetto per intercettare il traffico che mi interessa, ovvero IPv4
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        
		// Rimango in attesa dei pacchetti per gestirli, tramite il gestore dei pacchetti
		packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
	
		// Inizializzazione e avvio del Thread per il monitoraggio
        monRun = new MonitorRunnable();
		Thread monThread = new Thread(monRun);
		monThread.start();

        log.info("Firewall inizializzato.");
    }

    @Deactivate
    public void deactivate() {
		// Rimuovo il PacketProcessor custom e lo annullo per favorire la garbage collection
        packetService.removeProcessor(processor);
        processor = null;

		// Mando il segnale per l'arresto del thread di monitoraggio e di firewall
		monRun.setEnd();

        log.info("Firewall terminato.");
    }

    // METODO che esegue il flood del pacchetto, se possibile, altrimenti lo blocca
    private void flood(PacketContext context) {
        if (topologyService.isBroadcastPoint(topologyService.currentTopology(), context.inPacket().receivedFrom()))
            packetOut(context, PortNumber.FLOOD);
		else
            context.block();
    }

    // METODO che inoltra il pacchetto sulla porta desiderata
    private void packetOut(PacketContext context, PortNumber portNumber) {
        
		context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    // METODO che inoltra il pacchetto verso l host desiderato
    private void forward(PacketContext context, Host dst) {
		
		TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(dst.location().port()).build();
		
		OutboundPacket packet = new DefaultOutboundPacket(dst.location().deviceId(), treatment, context.inPacket().unparsed());
		packetService.emit(packet);
    }

    // METODO che installa una regola (intent) per l inoltro di un pacchetto sulla specifica porta.
    private void setIntent(PacketContext context, HostId srcId, HostId dstId) {

		// Gestisco tutti i pacchetti senza selezione, e la mia gestione non fa nulla di particolare
		TrafficSelector selector = DefaultTrafficSelector.emptySelector();
        TrafficTreatment treatment = DefaultTrafficTreatment.emptyTreatment();

		// Costruisco la chiave per l'intent
        Key key;
        if (srcId.toString().compareTo(dstId.toString()) < 0)
            key = Key.of(srcId.toString() + dstId.toString(), appId);
        else
            key = Key.of(dstId.toString() + srcId.toString(), appId);

		// Ricerco se l'intent e' eventualmente già presente
        HostToHostIntent intent = (HostToHostIntent) intentService.getIntent(key);
        
		// Se e' gia presente, controllo se è ancora valido o in stato di eliminazione (WITHDRAWN)
        if (intent != null) {
			
			// Se e' WITHDRAWN, lo rimpiazzo
            if (WITHDRAWN_STATES.contains(intentService.getIntentState(key))) {
                HostToHostIntent hostIntent = HostToHostIntent.builder()
                        .appId(appId)
                        .key(key)
                        .one(srcId)
                        .two(dstId)
                        .selector(selector)
                        .treatment(treatment)
                        .build();

                intentService.submit(hostIntent);
            }
			else
				// Se non è valido, droppo temporaneamente tutti i pacchetti relativi
				if (intentService.getIntentState(key) == IntentState.FAILED) {

					// Costruisco un oggetto che seleziona il traffico delle entita' in gioco
					TrafficSelector objectiveSelector = DefaultTrafficSelector.builder()
                        .matchEthSrc(srcId.mac()).matchEthDst(dstId.mac()).build();

					// Costruisco un oggetto che determina comportamento del controller
					TrafficTreatment dropTreatment = DefaultTrafficTreatment.builder()
                        .drop().build();

					// Costruisco un flusso temporaneo sulle basi di quanto ho creato
					ForwardingObjective objective = DefaultForwardingObjective.builder()
                        .withSelector(objectiveSelector)
                        .withTreatment(dropTreatment)
                        .fromApp(appId)
                        .withPriority(intent.priority() - 1)
                        .makeTemporary(DROP_RULE_TIMEOUT)
                        .withFlag(ForwardingObjective.Flag.VERSATILE)
                        .add();

					// e lo inoltro
					flowObjectiveService.forward(context.outPacket().sendThrough(), objective);
				}
		} 
		else // L'intent non esiste, lo creo
			if (intent == null) {
				HostToHostIntent hostIntent = HostToHostIntent.builder()
					.appId(appId)
                    .key(key)
                    .one(srcId)
                    .two(dstId)
                    .selector(selector)
                    .treatment(treatment)
					.priority(100)
                    .build();

				intentService.submit(hostIntent);
			} 
    }
	
	// METODO che setta la regola di blocco per il mac
    private void drop(MacAddress mac){

		// Ottengo l'id dell' host da bloccare
		HostId srcId = hostService.getHostsByMac(mac).toArray(new Host[1])[0].id();
		
		// Costruisco un oggetto che seleziona il traffico delle entita' in gioco
		TrafficSelector selector = DefaultTrafficSelector.builder().matchEthSrc(mac).build();
		
		// Costruisco un oggetto che determina comportamento del controller, ovvero di blocco
		TrafficTreatment treatment = DefaultTrafficTreatment.builder().drop().build();

	       	// Per ogni host, effettuo un monitoraggio
		for(Host h :  hostService.getHosts()) {
		
		// Costruisco la chiave per l'intent
		    Key key =  Key.of(srcId.toString() + h.id().toString() + "ban", appId);
		
		// Costruisco un intent sulle basi di quanto ho creato
		HostToHostIntent hostIntent = HostToHostIntent.builder()
			.appId(appId)
            .key(key)
            .one(srcId)
		    .two(h.id())
            .selector(selector)
            .treatment(treatment)
		    .priority(200)
            .build();

		// Confermo la regola di blocco
		intentService.submit(hostIntent); 
		}
		//Aggiungo il mac alla lista nera
		blacklist.add(mac);

		log.warn("Possible DoS detected, going to ban " + String.valueOf(mac));
    }

	// METODO che rimuove la regola di blocco per il mac
    private void undrop(MacAddress mac){
		
		// Ottengo l'id dell' host da bloccare
		HostId srcId = hostService.getHostsByMac(mac).toArray(new Host[1])[0].id();

	       	// Per ogni host, effettuo un monitoraggio
		for(Host h :  hostService.getHosts()) {
		
		// Costruisco la chiave per l'intent
		    Key key =  Key.of(srcId.toString() + h.id().toString() + "ban", appId);
		
		// Ottengo l'intent e lo setto come invalido, prima di rimuoverlo
		Intent toPurge = intentService.getIntent(key);
		intentService.withdraw(toPurge);
		while (!CAN_PURGE.contains(intentService.getIntentState(key)));
		intentService.purge(toPurge);

		}

		// Rimuovo il mac dalla lista nera di tutti gli oggetti
		blacklist.remove(mac);
		monRun.unban(mac);
		
		log.warn("DoS time expired, going to unban " + String.valueOf(mac));
    }
}
