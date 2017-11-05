/* SDN DDOS Mitigation Security Project @ CSUF Computing Lab
 * by Vincent Tran @vuqt1.uci.edu | Ver: 1.0 | July 18th, 2017
 * 
 * Purpose: Implementing Trigger UDP Flooding which follows the Trigger interface, please refer to my paper for more detail
 */
package net.floodlightcontroller.blackbox;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.Ethernet;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.types.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Trigger_UDPFlood implements Triggers {

	protected boolean isMonitoring = false;
	protected int happenTimes = 0;
	protected long timeStart = 0;
	protected MacAddress Mac_pre = null, Mac_now = null, Mac_block = null;
	protected static Logger logger;
	protected int numOfAttackPkts = 500, timeOut = 1000; //miliseconds

	@Override
	public boolean detect(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		logger = LoggerFactory.getLogger(Trigger_UDPFlood.class);
	
		if (!isMonitoring)
		{
			//Reset Timer T
			isMonitoring = true;
			timeStart = System.currentTimeMillis(); //Set timer
		}
		
		if ((System.currentTimeMillis() - timeStart) > timeOut) //Timer pass 1 second)
		{
			//reset monitoring
			logger.info("BLACKBOX: checkTrigger_UDP_Flood: RESET TIMER = 1 second ... ");
			happenTimes = 0;
			Mac_pre = null;
			isMonitoring = false;
			
		}
		else //Still within Timer interval T
		{
	        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
	        Mac_now = eth.getSourceMACAddress();
	        
			if (Mac_pre == null)
				{
					Mac_pre = Mac_now;
					happenTimes = 1;
				}
			else if (!Mac_now.equals(Mac_pre)) //Reset happenTimes b.c this is not continuous flooding packets.
				{
					Mac_pre = Mac_now;
					happenTimes = 1;
				}
			else 
				{ 
					happenTimes++;
					logger.info("BLACKBOX: checkTrigger_UDP_Flood: Detect continous number of packets: " + happenTimes + " from " + Mac_now);
					//logger.info("BLACKBOX: checkTrigger_UDP_Flood: Packets sent from the host address: " + Mac_now);

				}
				
			if (happenTimes > numOfAttackPkts) //call DDOSMitigation() here
				{
					Mac_block = Mac_pre;
					return true;
				}	
		}
		
		return false;	
	}
	
	public MacAddress getMACblock()
	{
		return Mac_block;
	}
	public void reset()
	{
		happenTimes = 0;
		timeStart = 0;
		Mac_pre = null;
		Mac_now = null;
		Mac_block = null;
	}

}
