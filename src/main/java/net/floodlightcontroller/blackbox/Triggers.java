/* SDN DDOS Mitigation Security Project @ CSUF Computing Lab
 * by Vincent Tran @vuqt1.uci.edu | Ver: 1.0 | July 18th, 2017
 * 
 * Purpose: Define  the Trigger interface, please refer to my paper for more detail
 */
package net.floodlightcontroller.blackbox;

import org.projectfloodlight.openflow.protocol.OFMessage;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFSwitch;

public interface Triggers {

	public boolean detect(IOFSwitch sw, OFMessage msg, FloodlightContext cntx);
	
}
