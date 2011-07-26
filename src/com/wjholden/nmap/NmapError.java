package com.wjholden.nmap;

import java.util.ArrayList;
import java.util.List;

import android.util.Log;

/**
 * NmapError is an error logging utility designed to save information
 * that previously went to Log.d. Many users do not know hot to get
 * debugging information from Logcat.
 * <br>
 * Before 0.4.8 there was an instance of NmapError that statically
 * referenced by everything else and it was messy and confusing.
 * Now, this class is a singleton (with a private constructor)
 * that everybody can access easily and should be great.
 * @author William John Holden (wjholden@gmail.com)
 * @version 0.2
 * @since 0.4.1
 */
public final class NmapError implements NmapConstants
{
	@SuppressWarnings("unused")
	private static final NmapError FINAL_INSTANCE = new NmapError();
	
	private final static List<String> ERROR_LOG = new ArrayList<String>();
	
	private NmapError()
	{
		// empty, private constructor establishes this as a Singleton.
	}
	
	/**
	 * Commit a new entry into the log.
	 * If Nmap.DEBUG is true then the entry will also output to Logcat.
	 * @param string The String Logged.
	 */
	public static void log(final String string)
	{
		if (string == null)
		{
			log("Log was given a null string.");
			return;
		}
		
		ERROR_LOG.add(string);
		if (NmapMain.debug)
		{
			Log.d(TAG, string);
		}
	}
	
	/**
	 * Grabs all lines of output previously stored using NmapError.Log(String).
	 * @return All lines of output, separated by newlines.
	 */
	public static String getLog()
	{
		final StringBuilder stringBuilder = new StringBuilder();
		final int stop = ERROR_LOG.size();
		for (int i = 0; i < stop; i++)
		{
			stringBuilder.append(ERROR_LOG.get(i));
			stringBuilder.append('\n');
		}
		return stringBuilder.toString();
	}
}
