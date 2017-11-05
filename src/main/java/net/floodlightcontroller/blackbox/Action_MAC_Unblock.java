/* SDN DDOS Mitigation Security Project @ CSUF Computing Lab
 * by Vincent Tran @vuqt1.uci.edu | Ver: 1.0 | July 18th, 2017
 * 
 * Purpose: One of Actions implementation is to unblock the attacking hosts, 
 * please refer to my paper for more detail
 */
package net.floodlightcontroller.blackbox;

import net.floodlightcontroller.core.IOFSwitch;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowDelete;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Action_MAC_Unblock implements Actions {

	protected MacAddress MAC_Unblocked = null;
	protected static Logger logger;
	protected OFFlowDelete flowDel;


	@Override
	public void execute(IOFSwitch sw) {

		logger = LoggerFactory.getLogger(Action_MAC_Unblock.class);
		if (MAC_Unblocked != null)
		{
			logger.warn("");
			logger.warn("BLACKBOX: $$$$$$$$$$$$$$ UNBLOCKED of ATTACKER's: " + MAC_Unblocked + " $$$$$$$$$$$$$$$$$\n");
			
			//Remove a flow of denial attacker host 
			OFFactory myFactoryDel = sw.getOFFactory(); //get the factory version of current running switch				
			Match myMatchDel = myFactoryDel.buildMatch().setExact(MatchField.ETH_SRC, MAC_Unblocked).build();			
			flowDel = myFactoryDel.buildFlowDelete().setMatch(myMatchDel).build();
			sw.write(flowDel);
		}

	}
	
	Action_MAC_Unblock(MacAddress MAC_Address)
	{
		MAC_Unblocked = MAC_Address;
	}

}
