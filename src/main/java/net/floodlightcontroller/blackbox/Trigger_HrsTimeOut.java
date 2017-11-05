/* SDN DDOS Mitigation Security Project @ CSUF Computing Lab
 * by Vincent Tran @vuqt1.uci.edu | Ver: 1.0 | July 18th, 2017
 * 
 * Purpose: Implementing Trigger Hours TimeOut which follows the Trigger interface, please refer to my paper for more detail
 */
package net.floodlightcontroller.blackbox;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFSwitch;

import org.projectfloodlight.openflow.protocol.OFMessage;

public class Trigger_HrsTimeOut implements Triggers {

	protected long setTimeOut_Start = 0;
	protected long setHrsTimeOut = 240000; //4 minutes for testing only, should be 24hrs = 86400000
	@Override
	public boolean detect(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {

		return (System.currentTimeMillis() - setTimeOut_Start > setHrsTimeOut);
	}
	
	public void setTimeOutBegin(long time)
	{
		setTimeOut_Start = time;
	}
	

}
