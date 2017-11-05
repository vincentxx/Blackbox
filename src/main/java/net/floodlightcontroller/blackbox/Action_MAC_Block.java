/* SDN DDOS Mitigation Security Project @ CSUF Computing Lab
 * by Vincent Tran @vuqt1.uci.edu | Ver: 1.0 | July 18th, 2017
 * 
 * Purpose: One of the Actions interface implementation is to block attacking hosts, 
 * please refer to my paper for more detail
 */
package net.floodlightcontroller.blackbox;

import net.floodlightcontroller.core.IOFSwitch;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Action_MAC_Block implements Actions {

	protected MacAddress MACblocked = null;
	protected static Logger logger;
	protected OFFlowAdd flowAdd;
	
	@Override
	public void execute(IOFSwitch sw) {
		
		if (MACblocked !=null)
		{
			//Insert a flow of denial attacker host by drop all his packets
			OFFactory myFactory = sw.getOFFactory(); //get the factory version of current running switch				
			Match myMatch = myFactory.buildMatch().setExact(MatchField.ETH_SRC, MACblocked).build();			
			flowAdd = myFactory.buildFlowAdd().setBufferId(OFBufferId.NO_BUFFER).setHardTimeout(3600).setIdleTimeout(0).setPriority(32768).setMatch(myMatch).build();
			sw.write(flowAdd);
	
			logger = LoggerFactory.getLogger(Action_MAC_Block.class);
			logger.warn("");
			logger.warn("BLACKBOX: $$$$$$$$$$$$$$ BLOCKED of ATTACKER's: " + MACblocked + " $$$$$$$$$$$$$$$$$\n");
		}
		
	}
	Action_MAC_Block(MacAddress MAC_Address)
	{
		MACblocked = MAC_Address;
	}

}
