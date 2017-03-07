Per cambiare il comportamento del firewall, modificare le variabili di MonitorHandler.java secondo queste istruzioni:

/*
 Limite di traffico che un host non deve superare in un ciclo
*/
public static final int BANDWIDTH = ?;
    
/*
 Numero di cicli consecutivi in cui l host deve superare il limite BANDWIDTH
*/
public static final int NUM_CYCLES = ?;

/*
 Tempo (in secondi) in cui il ban sara mantenuto
*/
public static final int BAN_TIME = ?;
