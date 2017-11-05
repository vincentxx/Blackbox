/* SDN DDOS Mitigation Security Project @ CSUF Computing Lab
 * by Vincent Tran @vuqt1.uci.edu | Ver: 1.0 | July 18, 2017
 * 
 * Purpose: Implementing the Blackbox FSM class, please refer to my paper for more detail
 */

package net.floodlightcontroller.blackbox;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


//This version is just for simple experiment only, the properties are explicitly declared. However, ideally 
//the states and other properties of FSM will be dynamically created by function built()
public class FSM {
	
	//States, Triggers, Actions
	public static final int No_Threat = 0, Low_Threat = 1 , After_Low_Threat_TimeOut = 2, High_Threat = 3;
	public static final int UDP_Flood = 0, Mins_TimeOut = 1, Hrs_TimeOut = 2;
	public static final int Block_MAC = 0, Unblock_MAC = 1, Null_Action = 2;
	protected int state[][];
	protected int action[][];
	protected int status = No_Threat;
	
	protected static Logger logger;
	
	FSM()
	{};
	
public void buildFSM() //This is just hard coding for experiment purpose only.
 	{
	logger = LoggerFactory.getLogger(FSM.class);
	logger.info("BLACKBOX: Initialize FSM starting....");
	
	//Refer FSM diagram @ vuqt1@uci.edu
	state = new int[4][3];
	action = new int [4][3];
	state[No_Threat][UDP_Flood] = Low_Threat;
	action[No_Threat][UDP_Flood] = Block_MAC;
	state[No_Threat][Mins_TimeOut] = No_Threat;
	action[No_Threat][Mins_TimeOut] = Null_Action;
	state[No_Threat][Hrs_TimeOut] = No_Threat;
	action[No_Threat][Hrs_TimeOut] = Null_Action;

	state[Low_Threat][UDP_Flood] = High_Threat; //happen for different attacking hosts
	action[Low_Threat][UDP_Flood] = Block_MAC;
	state[Low_Threat][Mins_TimeOut] = After_Low_Threat_TimeOut;
	action[Low_Threat][Mins_TimeOut] = Unblock_MAC;
	state[Low_Threat][Hrs_TimeOut] = No_Threat;
	action[Low_Threat][Hrs_TimeOut] = Unblock_MAC; //never happen for Block_MAC

	state[After_Low_Threat_TimeOut][UDP_Flood] = High_Threat;
	action[After_Low_Threat_TimeOut][UDP_Flood] = Block_MAC; 
	state[After_Low_Threat_TimeOut][Mins_TimeOut] = After_Low_Threat_TimeOut;
	action[After_Low_Threat_TimeOut][Mins_TimeOut] = Null_Action;
	state[After_Low_Threat_TimeOut][Hrs_TimeOut] = No_Threat;
	action[After_Low_Threat_TimeOut][Hrs_TimeOut] = Unblock_MAC;

	state[High_Threat][UDP_Flood] = High_Threat; //happen for different attacking hosts
	action[High_Threat][UDP_Flood] = Block_MAC;   //happen for different attacking host and is Block_MAC
	state[High_Threat][Mins_TimeOut] = High_Threat;
	action[High_Threat][Mins_TimeOut] = Null_Action;
	state[High_Threat][Hrs_TimeOut] = No_Threat;
	action[High_Threat][Hrs_TimeOut] = Unblock_MAC;

	logger.info("BLACKBOX: Initialize FSM completed....Ready for DDOS fighting");
	
	}
public int getStatus()
	{
		return status;
	}
public int getAction(int trigger)
	{
		return action[status][trigger];
	}
public void updateStatus(int trigger)
	{
		status = state[status][trigger] ;
	}
public void printStatus()
	{
	switch (status)
		{
			case No_Threat:
				logger.info("BLACKBOX: FSM Current Status of Detection: NO THREAT...");
				break;
			case Low_Threat:
				logger.info("BLACKBOX: FSM Current Status of Detection: LOW THREAT...");
				break;
			case After_Low_Threat_TimeOut:
				logger.info("BLACKBOX: FSM Current Status of Detection: AFTER MINUTES TIMEOUT - MONITORING...");
				break;
			case High_Threat:
				logger.info("BLACKBOX: FSM Current Status of Detection: HIGH THREAT...");
				break;
			default:
				logger.info("BLACKBOX: FSM Current Status of Detection: Something goes wrong..bug...");
				
		}
	}
}
