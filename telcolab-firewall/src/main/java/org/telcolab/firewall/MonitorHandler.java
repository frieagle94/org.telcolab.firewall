package org.telcolab.firewall;

import org.onlab.packet.MacAddress;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.Host;
import org.onosproject.net.HostLocation;
import org.onosproject.net.host.HostService;
import org.onosproject.net.device.PortStatistics;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.slf4j.Logger;

import java.util.*;

/**
 *
 * @author Riccardo Frigerio
 */

// OGGETTO che si occupa del monitoraggio del traffico
public class MonitorHandler {
    
    // Cicli di esecuzione
    private int current_time = 0;

    // Variabili di sistema
    private Logger log;
    private DeviceService deviceService;
    private HostService hostService;

    /*
      Traffico limite per un host in un ciclo
      (modificare per cambiare il comportamento del firewall)
    */
    public static final int BANDWIDTH = 140;
    
    /*
      Numero di cicli consecutivi in cui si deve verificare l oltrepassaggio del limite
      (modificare per cambiar il comportamento del firewall
    */
    public static final int NUM_CYCLES = 5;

    /*
      Secondi di ban per l host incriminato
      (modificare per cambiare il comportamento del firewall)
    */
    public static final int BAN_TIME = 10;

    // Mappa HOST, da mac address a quantita' di traffico
    private HashMap<MacAddress, Long[]> traffic = new HashMap<MacAddress, Long[]>();

    // Lista dei MAC degli host bloccati dal Firewall
    private ArrayList<MacAddress> blacklist = new ArrayList<MacAddress>();
    
    // COSTRUTTORE per le variabili di sistema
    public MonitorHandler(Logger log, DeviceService deviceService, HostService hostService){		
		this.log = log;
		this.deviceService = deviceService;
		this.hostService = hostService;
    }

    // METODO che monitora tutte le porte di tutti i device
    public void monitor() {

		// Ottengo gli host
		Iterable<Host> hosts = hostService.getHosts();

		// Per ogni host, effettuo un monitoraggio
		for(Host h : hosts) {

			// Ottengo info host, porta e device a cui e' connesso
			DeviceId device = h.location().deviceId();
			PortNumber port = h.location().port();
			MacAddress macAddress = h.mac();

			// Se l'host e' sconosciuto, lo aggiungo alla lista di quelli gia' monitorati
			if (!traffic.containsKey(macAddress))
				traffic.put(macAddress, new Long[NUM_CYCLES]);
    	   
			// Ottengo le statistiche delle porte del device
			List<PortStatistics> statList = deviceService.getPortStatistics(device);	   
	   
			// Se ad una porta corrisponde un host, monitoro il traffico     
			for (PortStatistics stat : statList){
				if (Long.valueOf(stat.port()) == port.toLong()) {
					Long rate = stat.bytesReceived() / 1024;
					traffic.get(macAddress)[current_time%NUM_CYCLES] = Long.valueOf(rate);
					break;
				}
			}
			
			try {
			    // Cerco il valore che mi interessa nell'array delle rilevazioni
			    int temp = current_time%NUM_CYCLES + 1;
			    if (current_time%NUM_CYCLES == NUM_CYCLES - 1)
				temp = 0;
	    
			    // Cerco un ban se solo e' passato un tempo sufficientemente lungo dall'inizio dell'esecuzione 
			    if(current_time > NUM_CYCLES)
					/* Se il traffico cumulato delle ultime limit.cycles rilevazioni supera limit.bandiwidth
						banno l'host se non e' gia' stato fatto
					*/
					if((traffic.get(macAddress)[current_time%NUM_CYCLES] - traffic.get(macAddress)[temp]) > BANDWIDTH*NUM_CYCLES && 
					!blacklist.contains(macAddress))
						ban(macAddress);
						
			} catch (NullPointerException e) {/*Non fare nulla, al prossimo ciclo sarà tutto ok*/}
			
		}
		// Aggiorno la conole
		updateConsole();

		// Incremento il tempo globale
		current_time++;
		
    }

    // METODO che aggiorna il log a video
    public void updateConsole(){
 	        
		// Loggo tutti gli host
		log.info("      Host        || Rate");
		
		for (Map.Entry <MacAddress,Long[]> entry : traffic.entrySet())
			log.info(String.valueOf(entry.getKey()) + " || " + entry.getValue()[current_time%NUM_CYCLES] + " KB");

		// Loggo gli host bloccati
		if(!blacklist.isEmpty()){

			log.info("");
			log.warn("---Currently Banned Host---");

			for (MacAddress mac : blacklist)
				log.warn(String.valueOf(mac));
		}
    }

    // METODO che aggiunge un host alla blacklist
    public void ban(MacAddress macAddress){
		blacklist.add(macAddress);
    }

    // METODO che rimuove un host dalla blacklist
    public void unban(MacAddress macAddress){
		blacklist.remove(macAddress);
    }    

    // GETTERS

	// METODO che restituisce un Set dei MAC degli host bloccati
    public ArrayList<MacAddress> getDoS(){
		return blacklist;
    }

	// METODO che restituisce una statistica di traffico del MAC desiderato tra le ultime NUM_CYCLES rilevate
    public Long getTraffic(MacAddress macAddress, int index){
		return traffic.get(macAddress)[index];
    }
}
