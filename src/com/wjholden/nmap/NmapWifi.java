package com.wjholden.nmap;

import android.content.Context;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Message;
import android.text.format.Formatter;

/**
 * Thread that watches for changes in the SSID/IP on 802.11 and
 * requests NmapMain.handler update the UI.
 * 
 * @author William John Holden (wjholden@gmail.com)
 * @version 0.1
 * @since 0.5.1
 */
public class NmapWifi extends Thread implements NmapConstants {
	
	private final Context context;
	private String ssid;
	private String ipAddress;
	private boolean disconnectAlreadyAnnounced = false;
	
	/**
	 * Set NmapWifi.closing to true to close the thread. 
	 */
	public static boolean closing = false;
		
	public NmapWifi(Context context)
	{
		this.context = context;
	}
	
	public void run()
	{
		do
		{
			showWifiInfo();
			try
			{
				Thread.sleep(3000);
			}
			catch (Exception e)
			{
				NmapError.log("NmapWifi bailed: " + e.toString());
			}
		} while (!closing);
	}
	
	/**
	 *  Try to get the SSID and IP. If you get it, set the users title to reflect this information.
	 */
	private void showWifiInfo()
	{
		final WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
		final WifiInfo wifiInfo = wifiManager.getConnectionInfo();
		final String newSsid = wifiInfo.getSSID();
		final String newIpAddress = Formatter.formatIpAddress(wifiInfo.getIpAddress());
		if (newSsid != null && newIpAddress != null && (ssid == null || ipAddress == null) && !(newSsid.equals(ssid) && newIpAddress.equals(ipAddress)))
		{
			ssid = newSsid;
			ipAddress = newIpAddress;
			final String output = "  SSID: " + ssid + "  IP: " + ipAddress;
			Message msg = Message.obtain();
			msg.what = SET_TITLE;
			msg.obj = output;
			NmapMain.handler.sendMessage(msg);
		}
		else
		{
			if (!disconnectAlreadyAnnounced)
			{
				NmapError.log("Not connected to any 802.11 wireless network.");
				disconnectAlreadyAnnounced = true;
			}
		}
	}
}
