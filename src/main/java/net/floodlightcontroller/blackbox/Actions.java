/* SDN DDOS Mitigation Security Project @ CSUF Computing Lab
 * by Vincent Tran @vuqt1.uci.edu | Ver: 1.0 | July 18th, 2017
 * 
 * Purpose: Implementing the Actions interface, please refer to my paper for more detail
 */
package net.floodlightcontroller.blackbox;


import net.floodlightcontroller.core.IOFSwitch;

public interface Actions {
	public void execute(IOFSwitch sw);

}
