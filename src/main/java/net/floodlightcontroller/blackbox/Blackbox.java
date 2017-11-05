/* SDN DDOS Mitigation Security Project @ CSUF Computing Lab
 * by Vincent Tran @vuqt1.uci.edu | Ver: 2.0 | July 18th, 2017
 * 
 * Purpose: Implementing new algorithm component named Blackbox 
 * for mitigating the DDOS on SDN Network
 *
 * Ideas: Blackbox is  implemented by using Finite State Machine theory
 * with (Triggers - Actions) = (Input - Output) for decision making mechanism. 
 * 
 * Note: This is just a very simple implement of Blackbox big idea. 
 * Because of resource and time limit in my Summer Proj URE, 
 * I just implement Blackbox which defend agaist 1 type of DDoS attack: UDP_Flooding. 
 * I wish I could implement other type of DDoS Triggers such as SYN flood, ICMP flood, etc.
 */



package net.floodlightcontroller.blackbox;

import java.util.Collection;
import java.util.LinkedList;
import java.util.Map;
import java.util.ArrayList;
import java.util.Queue;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.MacAddress;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.blackbox.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



public class Blackbox implements IOFMessageListener, IFloodlightModule {
	
	//Member variables and properties
	protected IFloodlightProviderService floodlightProvider;
	protected static Logger logger;
	//FSM
	protected FSM theFSM;
	//Triggers
	protected Trigger_UDPFlood theTriggerUDP;
	protected Trigger_MinsTimeOut theTriggerMinsTimeOut;
	protected Trigger_HrsTimeOut theTriggerHrsTimeOut;
	//Actions
	protected Actions theAction;
	protected Queue<MacAddress> Mac_block_queue;
	protected Queue<IOFSwitch> IOFSwitch_Macblock_queue;

	
	public String getName() {
		//return self simple name
		return Blackbox.class.getSimpleName();
	}

	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		
		// Add this module to the module loading system
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		
		//Init primarily is run load dependencies and initialize data structures 
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
	    logger = LoggerFactory.getLogger(Blackbox.class);
	    
	    //Init Blackbox
	    initBlackbox();
	}

	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		//when startup handles PACKET_IN through the module OFMessageListener
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	//Handle PACKET_IN threads
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {

		if (msg.getType() == OFType.PACKET_IN)
		{			
			//Call intellect Blackbox algorithm for monitor, identify & response security attacks
			handle_UDPAttacks_Algorithm(sw, msg, cntx); 
		}
	
	  return Command.CONTINUE;
	}
	
	//Init Blackbox FSM
	protected void initBlackbox()
	{
		logger.info("BLACKBOX: Initialize FSM starting....");
		theFSM = new FSM();
		theFSM.buildFSM();
		theTriggerUDP = new Trigger_UDPFlood();
		theTriggerMinsTimeOut = new Trigger_MinsTimeOut();
		theTriggerHrsTimeOut = new Trigger_HrsTimeOut();
		Mac_block_queue = new LinkedList<MacAddress>();
		IOFSwitch_Macblock_queue = new LinkedList<IOFSwitch>();

	}
	
	//How would you handle DDOS attack? this is simple way to handle UDP Flooding
	protected void handle_UDPAttacks_Algorithm(IOFSwitch sw, OFMessage msg, FloodlightContext cntx)
	{
		if(theTriggerUDP.detect(sw, msg, cntx))
		{
			//take Action then update FSM status
			MacAddress Mac_block = theTriggerUDP.getMACblock();
			theAction = new Action_MAC_Block(Mac_block);
			theAction.execute(sw);
			theFSM.updateStatus(FSM.UDP_Flood);
			
			//Record the black list
			Mac_block_queue.add(Mac_block);
			IOFSwitch_Macblock_queue.add(sw);

			//Set TimeOut start
			theTriggerUDP.reset();
			theTriggerMinsTimeOut.setTimeOutBegin(System.currentTimeMillis());
			theTriggerHrsTimeOut.setTimeOutBegin(System.currentTimeMillis());
			logger.info("The status of FSM " + theFSM.getStatus());
			theFSM.printStatus();
		}
		else if (theTriggerMinsTimeOut.detect(sw, msg, cntx))
		{
			if (FSM.Unblock_MAC == theFSM.getAction(FSM.Mins_TimeOut) && !Mac_block_queue.isEmpty())
				{
					logger.warn("BLACKBOX: ##################### UNBLOCK DUE TO MINS TIMEOUT #########");
					logger.warn("BLACKBOX: ##################### UNBLOCK DUE TO MINS TIMEOUT #########");
					
					theAction = new Action_MAC_Unblock(Mac_block_queue.poll());
					theAction.execute(IOFSwitch_Macblock_queue.poll());
					theFSM.updateStatus(FSM.Mins_TimeOut);
					theFSM.printStatus();
				}
		}
		else if (theTriggerHrsTimeOut.detect(sw, msg, cntx))
		{
			if (FSM.Unblock_MAC == theFSM.getAction(FSM.Hrs_TimeOut) && !Mac_block_queue.isEmpty())
			{
				logger.warn("BLACKBOX: ##################### UNBLOCK DUE TO HOURS TIMEOUT #########");
				logger.warn("BLACKBOX: ##################### UNBLOCK DUE TO HOURS TIMEOUT #########");
				
				//Recovery of black list after hrs timeout, back to S0
				while (!Mac_block_queue.isEmpty() && !IOFSwitch_Macblock_queue.isEmpty() )
				{
					theAction = new Action_MAC_Unblock(Mac_block_queue.poll());
					theAction.execute(IOFSwitch_Macblock_queue.poll());
				}
				theFSM.updateStatus(FSM.Hrs_TimeOut);
				theFSM.printStatus();
			}
		}
		
	}


	//Functions are not implemented in the Interface
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

}
