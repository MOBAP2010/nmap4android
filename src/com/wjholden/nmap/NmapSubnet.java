package com.wjholden.nmap;

import java.nio.ByteOrder;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.DhcpInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.EditText;

/**
 * Shows information about the subnet the device is currently connected to via
 * 802.11. This class includes a number of methods handling the confusing world
 * of byte ordering with IP's in Java. There is no 'unsigned byte' in Java so
 * portions of this were (very) frustrating to write, but it's been fun and
 * educational.<br />
 * <b>TODO</b>:<br />
 *  - save output to XML<br />
 *  - enable/disable debugging from here
 * @author William John Holden (wjholden@gmail.com)
 * @version 0.1
 * @since 30
 */
public class NmapSubnet extends Activity implements NmapConstants {

	static Handler handler;
	static PollWifiChanges poller;
	static boolean subnetActivityClosing;

	private transient EditText editIP;
	private transient EditText editDG;
	private transient EditText editSM;
	private transient EditText editNet;
	private transient EditText editBC;
	private transient EditText editHosts;
	private transient EditText editDns1;
	private transient EditText editDns2;
	private transient EditText editClass;
	private transient EditText editSSID;
	
	private transient int ip[];
	private transient int mask[];
	private transient int gateway[];
	private transient int network[];
	private transient int broadcast[];
	private transient int dns1[];
	private transient int dns2[];
	private transient String classfulness;
	private transient String ssid;
	
	private transient int base = MI_DEC;
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		this.setContentView(R.layout.subnet);
		editIP = (EditText) findViewById(R.id.editTextIP);
		editDG = (EditText) findViewById(R.id.editTextDG);
		editSM = (EditText) findViewById(R.id.editTextSM);
		editNet = (EditText) findViewById(R.id.editTextNet);
		editBC = (EditText) findViewById(R.id.editTextBC);
		editHosts = (EditText) findViewById(R.id.editTextHosts);
		editDns1 = (EditText) findViewById(R.id.editTextDNS1);
		editDns2 = (EditText) findViewById(R.id.editTextDNS2);
		editClass = (EditText) findViewById(R.id.editTextClass);
		editSSID = (EditText) findViewById(R.id.editTextSSID);
		
		handler = new Handler(){
			public void handleMessage(Message msg) {
				switch (msg.what) {
				case SUBNET_CONNECTED:
					NmapError.log("Wifi is connected. Updating view...");
					getWifiInfo();
					break;
				case SUBNET_DISCONNECTED:
					NmapError.log("Wifi not connected. Clearing view...");
					clearView();
					break;
				default:
					// do nothing
					break;
				}
			}
		};
		
		if (poller == null || !poller.isAlive())
		{
			subnetActivityClosing = false;
			poller = new PollWifiChanges(SUBNET_POLL_INTERVAL);
			poller.start();
		}
	}

	/**
	 * Clears all fields in the viewport.
	 */
	private void clearView()
	{
		editIP.setText("");
		editDG.setText("");
		editSM.setText("");
		editNet.setText("");
		editBC.setText("");
		editHosts.setText("");
		editDns1.setText("");
		editDns2.setText("");
		editClass.setText("");
		editSSID.setText("");
	}
	
	/**
	 * This method calls other methods, as appropriate, to gather and calculate
	 * information on the subnet the handset it currently connected to via 802.11.
	 * Also updates UI directly.
	 * @return String summary of all information gathered, for ease of use when e-mailing output.
	 */
	private String getWifiInfo()
	{
		final WifiManager wifiManager = (WifiManager) this.getSystemService(Context.WIFI_SERVICE);
		final DhcpInfo dhcp = wifiManager.getDhcpInfo();
		final int numberOfHosts;
		final int cidr;
		
		ip = ipToArray(dhcp.ipAddress);
		mask = ipToArray(dhcp.netmask);
		gateway = ipToArray(dhcp.serverAddress);
		network = new int[4];
		for (int i = 0; i < 4 ; i++)
		{
			network[i] = ip[i] & mask[i];
		}
		broadcast = broadcast(network, dhcp.netmask);
		dns1 = ipToArray(dhcp.dns1);
		dns2 = ipToArray(dhcp.dns2);
		classfulness = findNetworkClass(network, dhcp.netmask);
		
		numberOfHosts = subnetNumberOfHosts(ipArrayToInt(mask));
		cidr = cidr(dhcp.netmask);
		
		final WifiInfo wifiInfo = wifiManager.getConnectionInfo();
		ssid = wifiInfo.getSSID();
		if (ssid == null)
		{
			ssid = "Not Connected";
		}

		final String info =
			"Host IP Address   = " + ipToString(ip, ByteOrder.LITTLE_ENDIAN, base) + "\n" +
			"Default Gateway   = " + ipToString(gateway, ByteOrder.LITTLE_ENDIAN, base) + "\n" +
			"Subnet Mask       = " + ipToString(mask, ByteOrder.LITTLE_ENDIAN, base) + "\n" + 
			"Network Address   = " + ipToString(network, ByteOrder.LITTLE_ENDIAN, base) + "/" + cidr + "\n" + 
			"Broadcast Address = " + ipToString(broadcast, ByteOrder.BIG_ENDIAN, base) + "\n" +
			"Number of Hosts   = " + numberOfHosts + "\n" +
			"DNS 1             = " + ipToString(dns1, ByteOrder.LITTLE_ENDIAN, base) + "\n" + 
			"DNS 2             = " + ipToString(dns2, ByteOrder.LITTLE_ENDIAN, base) + "\n" + 
			"Class             = " + classfulness + "\n" + 
			"SSID              = " + ssid;
		NmapError.log(info);

		editIP.setText(ipToString(ip, ByteOrder.LITTLE_ENDIAN, base));
		editDG.setText(ipToString(gateway, ByteOrder.LITTLE_ENDIAN, base));
		editSM.setText(ipToString(mask, ByteOrder.LITTLE_ENDIAN, base));
		editNet.setText(ipToString(network, ByteOrder.LITTLE_ENDIAN, base) + "/" + cidr);
		editBC.setText(ipToString(broadcast, ByteOrder.BIG_ENDIAN, base));
		editHosts.setText(numberOfHosts + "");
		editDns1.setText(ipToString(dns1, ByteOrder.LITTLE_ENDIAN, base));
		editDns2.setText(ipToString(dns2, ByteOrder.LITTLE_ENDIAN, base));
		editClass.setText(classfulness);
		editSSID.setText(ssid);
		
		return info;
	}
	
	/**
	 * Finds the network class of a network given network address and subnet mask.
	 * TODO what IP are you throwing at this?  Check the parameters of calling function.
	 * Ok, that's right - use a bit shift so you can compare only the digits you really need.
	 * @param ip Network-order IP address of the network IP.
	 * @param subnet Host-order IP in integer format.
	 * @return String indicating class letter and whether classful or classless.
	 */
	private String findNetworkClass(final int ip[], final int subnet)
	{
		final StringBuilder networkClass = new StringBuilder();
		final int cidr = cidr(subnet);
		final byte fb = (byte) ip[0];
		
		if ((~fb & 0x80) == 0x80) // is first digit zero [0x80 = b10000000]
		{
			networkClass.append("Class A");
			networkClass.append(networkClassfulness('A', cidr));
		}
		else if ((fb & 0x80) == 0x80 && (~fb & 0x40) == 0x40) // is second digit zero [0x40 = b01000000]
		{
			networkClass.append("Class B");
			networkClass.append(networkClassfulness('B', cidr));
		}
		else if ((fb & 0xC0) == 0xC0 && (~fb & 0x20) == 0x20) // is third digit zero [0x20 = b00100000]
		{                                                     //                     [0xC0 = b11000000]
			networkClass.append("Class C");
			networkClass.append(networkClassfulness('C', cidr));
		}
		else if ((fb & 0xE0) == 0xE0 && (~fb & 0x10) == 0x10) // is fourth digit zero [0x10 = b00010000]
		{                                                     //                      [0xE0 = b11100000]
			networkClass.append("Multicast");
		}
		else if (fb == 0xFF)
		{
			networkClass.append("Broadcast");
		}
		else
		{
			networkClass.append("Experimental");
		}
		
		return networkClass.toString();
	}
	
	/**
	 * Basic logic to determine, given class and CIDR, whether a network is classful or classless.
	 * @param classChar Character representation of class ('A', 'B', or 'C').
	 * @param cidr Number of bits used for subnet/network address (i.e. 192.168.1.1/xx <- xx is the CIDR).
	 * @return String telling you whether it's classful or classless.
	 */
	private String networkClassfulness(final char classChar, final int cidr)
	{
		if ((classChar - 'A' + 1) * 8 == cidr)
		{
			return " (Classful)";
		}
		else
		{
			return " (Classless)";
		}
	}
	
	/**
	 * Calculates the broadcast address for given network using given subnet.
	 * Since Android gives us the subnet as an integer we can just use what's
	 * already given by the API and not reinvent the wheel.
	 * @param network Integer-array formed network address.
	 * @param subnet Subnet provided by DhcpInfo.netmask.
	 * @return Integer-array broadcast address for subnet.
	 */
	private int[] broadcast(final int network[], final int subnet)
	{
		return ipToArray(ipArrayToInt(network) + subnetNumberOfHosts(subnet) + 1);
		// network + number of hosts (maximum #, so -2 giving space for net & bc) + 1 (+1 is the bc addr)
	}
	
	/**
	 * Converts an IP address in integer-array form to a String.
	 * Because different methods in this program handle IP's in
	 * big- and little-endian format this method requires the
	 * developer to specify which is desired. If unknown, call
	 * java.nio.ByteOrder.nativeOrder().<br />
	 * IPv4 only.
	 * @param ip Integer-array IPv4 address.
	 * @param endianness ByteOrder.LITTLE_ENDIAN or ByteOrder.BIG_ENDIAN.
	 * @param base Indicates what base to output in (options are MI_DEC, MI_HEX, and MI_BIN,
	 * as defined in NmapConstants interface).
	 * @return String dot-decimal representation of IPv4 address.
	 */
	private String ipToString(final int ip[], ByteOrder endianness, int base)
	{
		String ipString = null;
		if (endianness == ByteOrder.LITTLE_ENDIAN)
		{
			switch (base)
			{
			case MI_DEC:
				ipString = ip[3] + "." + ip[2] + "." + ip[1] + "." + ip[0];
				break;
			case MI_HEX:
				ipString = String.format("%02x", ip[3]) + "." + String.format("%02x", ip[2]) + "." +
				String.format("%02x", ip[1]) + "." + String.format("%02x", ip[0]);
				break;
			case MI_BIN:
				StringBuilder sb = new StringBuilder();
				for (int i=ip.length - 1; i>= 0; i--)
				{
					String binstr = Integer.toBinaryString(ip[i]);
					for (int k=0; k<8-binstr.length();k++)
						sb.append('0');
					sb.append(Integer.toBinaryString(ip[i]));
					if (i > 0)
					{
						sb.append('.');
					}
				}
				ipString = sb.toString();
				break;
			default:
				NmapError.log("No format specified for ipToString.");
				break;
			}
		}
		else
		{
			switch (base)
			{
			case MI_DEC:
				ipString = ip[0] + "." + ip[1] + "." + ip[2] + "." + ip[3];
				break;
			case MI_HEX:
				ipString = String.format("%02x", ip[0]) + "." + String.format("%02x", ip[1]) + "." +
				String.format("%02x", ip[2]) + "." + String.format("%02x", ip[3]);
				break;
			case MI_BIN:
				StringBuilder sb = new StringBuilder();
				for (int i=0; i<ip.length; i++)
				{
					String binstr = Integer.toBinaryString(ip[i]);
					for (int k=0; k<8-binstr.length();k++)
						sb.append('0');
					sb.append(Integer.toBinaryString(ip[i]));
					if (i < ip.length - 1)
					{
						sb.append('.');
					}
				}
				ipString = sb.toString();
				break;
			default:
				NmapError.log("No format specified for ipToString.");
				break;
			}
		}
		return ipString;
	}
	
	/**
	 * Uses the CIDR method to calculate the number of hosts available based
	 * off of the provided subnet mask. Remember, the number of hosts is two
	 * fewer than two to the power of host bits because the first IP address
	 * is the network and last is the broadcast.
	 * @param subnet Host byte representation of the subnet mask.
	 * @return Maximum possible number of hosts in this network.
	 */
	private int subnetNumberOfHosts(final int subnet)
	{
		int subnetSize = (int) Math.pow(2, 32 - cidr(subnet)) - 2;
		NmapError.log("Subnet Size = " + (subnetSize));
		return subnetSize;
	}
	
	/**
	 * Calculates the number of bits used for the network+subnet based off of
	 * given subnet mask.
	 * @param subnet Host byte representation of the subnet mask.
	 * @return CIDR-style number of network bites (i.e. 192.168.1.0/<b>24</b>).
	 */
	private int cidr (final int subnet)
	{
		int mySubnet[] = ipToArray(subnet);
		short numberOfOnes = 0;
		for (int i = 0; i < mySubnet.length; i++)
		{
			int ones = subnetNumberOfOnes(mySubnet[i]);
			numberOfOnes += ones;
			NmapError.log(ones + " ones found in byte " + i + " (" + mySubnet[i] + ") in mask " + ipToString(mySubnet, ByteOrder.BIG_ENDIAN, MI_DEC));
		}
		return numberOfOnes;
	}
	
	/**
	 * Counts the number of ones in the binary representation of a single octet of your subnet mask.<br />
	 * Note that this was not designed for wildcard masks (i.e. 0.0.3.255); invert in that case
	 * (i.e. <i>subnetNumberOfZeros(octet & 0xFF)</i>).
	 * @param octet An IPv4-style octet values 0 to 255.
	 * @return Number of ones found in given subnet mask byte, Integer.MIN_VALUE on error.
	 * Returning Integer.MIN_VALUE makes it obvious to the developer and end user that a serious
	 * problem has occured that needs to be tracked down.
	 */
	private int subnetNumberOfOnes(final int octet)
	{
		if (octet > 255 || octet < 0)
		{
			NmapError.log("subnetNumberOfZeros received invalid input " + octet);
			return(Integer.MIN_VALUE);
		}
		/*
		Power(2):	7	6	5	4	3	2	1	0
		Value(2^n):	128	64	32	16	8	4	2	1
		Mask Byte:	128	192	224	240	248	252	254	255
		*/
		int bitsum = 0;
		short i = 8;
		for ( ; i > - 1 && bitsum < octet; i--) // -1 so we can catch errors where octet was not a valid value.
		{
			bitsum += Math.pow(2, i - 1);
		}
		if (i == -1)
		{
			NmapError.log("subnetNumberOfZeros cannot find mask to satisify input " + octet);
			return(Integer.MIN_VALUE);
		}
		return 8 - i;
	}
	
	/**
	 * This is some good stuff I borrowed from <a href="http://teneo.wordpress.com/2008/12/23/java-ip-address-to-integer-and-back/">
	 * this guy</a>, who in turn says it came from Limewire. Go figure.<br />
	 * Automatically detects native byte order and (hopefully) makes the correct byte assignments. So you can use this on
	 * big or little endian platforms. I realize that Android IA/32 (ARM) will probably always be little endian but I like
	 * robust, reusable code.<br />
	 * <b>Caveats</b>:<ul>
	 * <li>IPv4 only.</li>
	 * <li>Big-Endian logic has not been tested.</li>
	 * <li>Integers should always be returned positive or zero, but they <i>are</i> signed integers internally.</li>
	 * </ul>
	 * @param ip Integer representation in host byte order to be converted.
	 * @return Integer array in network byte order representing an IPv4 address.
	 */
	private int[] ipToArray(final int ip)
	{
		int newIp[] = new int[4];
		if (ByteOrder.nativeOrder() == ByteOrder.LITTLE_ENDIAN) {
			newIp[0] = ((ip >> 24) & 0xFF);
			newIp[1] = ((ip >> 16) & 0xFF);
			newIp[2] = ((ip >> 8) & 0xFF);
			newIp[3] = ((ip) & 0xFF);
		} else {
			newIp[3] = ((ip >> 24) & 0xFF);
			newIp[2] = ((ip >> 16) & 0xFF);
			newIp[1] = ((ip >> 8) & 0xFF);
			newIp[0] = ((ip) & 0xFF);
		}
		return newIp;
	}
	
	/**
	 * Converts an integer-array IPv4 address back to an integer representation.
	 * @param input Integer-array IPv4 address in network byte order.
	 * @return Integer IPv4 address in host byte order.
	 */
	private int ipArrayToInt(final int input[])
	{
		int ipInt;
		if (java.nio.ByteOrder.nativeOrder() == java.nio.ByteOrder.LITTLE_ENDIAN) {
			ipInt = (input[3] << 24) + (input[2] << 16) + (input[1] << 8) + input[0];
		} else {
			ipInt = (input[0] << 24) + (input[1] << 16) + (input[2] << 8) + input[3];
		}
		return ipInt;
	}
	
	private class PollWifiChanges extends Thread implements NmapConstants
	{
		private int pollInterval;

		public PollWifiChanges(final int pollInterval)
		{
			this.pollInterval = pollInterval;
		}
		
		public void run()
		{
			final WifiManager wifiManager = (WifiManager) NmapSubnet.this.getSystemService(Context.WIFI_SERVICE);
			NmapError.log("Wifi polling thread started.");
			int countConnected = 0; // when you're connected, only poll three times.  There's really no reason to
			// continue polling once you've got all the information needed.
			do
			{
				final WifiInfo wifiInfo = wifiManager.getConnectionInfo();
				boolean isConnected = (wifiInfo.getSSID() != null);
				if (isConnected)
				{
					handler.sendEmptyMessage(SUBNET_CONNECTED);
					pollInterval = 5000; // slow the thread down if you're connected
					countConnected++;
				}
				else
				{
					handler.sendEmptyMessage(SUBNET_DISCONNECTED);
					pollInterval = 1000; // keep the thread fast if you're not connected
				}
				try {
					Thread.sleep(pollInterval);
				} catch (InterruptedException e) {
					NmapError.log(e.toString());
					NmapSubnet.subnetActivityClosing = true;
				}
			} while (!NmapSubnet.subnetActivityClosing && countConnected < 3);
			NmapError.log("Wifi polling thread closed.");
		}
	}


	@Override
	protected void onDestroy() {
		NmapError.log("Subnet Activity closed.");
		subnetActivityClosing = true;
		poller = null;
		super.onDestroy();
	}

	/* (non-Javadoc)
	 * @see android.app.Activity#onMenuItemSelected(int, android.view.MenuItem)
	 */
	@Override
	public boolean onMenuItemSelected(int featureId, MenuItem item) {
		switch (item.getItemId())
		{
		case MI_DEC:
		case MI_HEX:
		case MI_BIN:
			base = item.getItemId(); 
			getWifiInfo();
			break;
		case MI_EMAIL_SUBNET:
			final String info = getWifiInfo();	
			final Intent emailIntent = new Intent(android.content.Intent.ACTION_SEND);
			emailIntent.setType("plain/text");
			emailIntent.putExtra(android.content.Intent.EXTRA_SUBJECT, "Subnet Information for " + ssid);
			emailIntent.putExtra(android.content.Intent.EXTRA_TEXT, info);
			NmapSubnet.this.startActivity(emailIntent);
			break;
		default:
			NmapError.log("Unrecognized item selected in NmapSubnet: " + item.getItemId());
			break;
		}
		return super.onMenuItemSelected(featureId, item);
	}

	/* (non-Javadoc)
	 * @see android.app.Activity#onPrepareOptionsMenu(android.view.Menu)
	 */
	@Override
	public boolean onPrepareOptionsMenu(Menu menu) {
		menu.removeGroup(MG_SUBNET);
		menu.add(MG_SUBNET, MI_DEC, Menu.NONE, "Decimal");
		menu.add(MG_SUBNET, MI_HEX, Menu.NONE, "Hexidecimal");
		menu.add(MG_SUBNET, MI_BIN, Menu.NONE, "Binary");
		menu.add(MG_SUBNET, MI_EMAIL_SUBNET, Menu.NONE, "Email Output");
		return super.onPrepareOptionsMenu(menu);
	}

}
