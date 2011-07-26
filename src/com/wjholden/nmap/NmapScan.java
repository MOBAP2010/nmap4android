package com.wjholden.nmap;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;

import android.content.pm.PackageManager.NameNotFoundException;
import android.os.AsyncTask;
import android.os.Message;

/**
 * Perform the actual scan.<br />
 * 0.4.5:<br />
 * - moved many local variables to private visibility<br />
 * - utilized previously unused NmapError class.<br />
 * Context isn't needed for this class, but it <i>is</i> needed in NmapInstall class for Resources.
 * @author William John Holden (wjholden@gmail.com)
 */
// Object[1]=String, Object[0]=Context
// Turns out the Context isn't even needed.
public class NmapScan extends AsyncTask <String, Void, Void> implements NmapConstants
{
	private transient String command;
	private transient String shell;
	private transient String outputArgs;
	private transient String bindir;
	private transient long startTime;
	
	//private transient DataOutputStream outputStream;
	//private transient BufferedReader inputStream;
	//private transient BufferedReader errorStream;
	//private transient Process process;

	protected void onPreExecute()
	{
		startTime = System.currentTimeMillis();
		NmapMain.handler.sendEmptyMessage(SCAN_STARTED);
		switch (NmapMain.scanType) {
			case SCANTYPE_ATRIX:
				command = "nmap_atrix ";
				break;
			case SCANTYPE_NMAP_SVN:
				command = "nmap ";
				break;
			case SCANTYPE_NPING:
				command = "nping ";
				break;
			case SCANTYPE_NDIFF:
				command = "ndiff ";
				break;
			case SCANTYPE_NCAT:
				command = "ncat ";
				break;
			default:
				command = "nmap ";
				break;
		}
		
		if (NmapUtilities.canGetRoot)
		{
			command += " --privileged "; // was NmapMain.outputArgs originally
		}
		else
		{
			command += " --unprivileged ";
		}
		
		bindir = NmapUtilities.findBinDir();
		shell = NmapUtilities.checkRootPermissions();

		NmapError.log("Selected scan type: " + command + " (" + NmapMain.scanType + ")");
	}

	protected void onPostExecute(final Void myVoid)
	{
		if (NmapMain.progressDialog != null)
		{
			NmapMain.progressDialog.dismiss();
		}
		NmapMain.hasRunOneScan = true;
	}

	@Override
	protected Void doInBackground(final String... params) {
		final String exeParams = (String) params[0];
		Process process;
		DataOutputStream outputStream;
		BufferedReader inputStream;
		BufferedReader errorStream;

		if (NmapUtilities.canGetRoot)
		{
			NmapError.log("Getting root...");
		}
		
		try {
			final String temporaryFolder = NmapUtilities.verifyTemporaryFolder();
			if (NmapMain.scanType == SCANTYPE_NMAP_SVN || NmapMain.scanType == SCANTYPE_ATRIX)
			{
				outputArgs = " -oA " + temporaryFolder + "/nmap ";
				NmapError.log("outputArgs =" + outputArgs);
				command += outputArgs;
			}
		} catch (NameNotFoundException e1) {
			NmapError.log(e1.getMessage());
		} catch (IOException e1) {
			NmapError.log(e1.getMessage());
		}
		
		try {
			process = Runtime.getRuntime().exec(shell);
			if (process == null)
			{
				final Message msg = Message.obtain();
				msg.obj = "Serious error: process == null. Please contact developer for assistance.";
				msg.what = RUN_ERROR;
				NmapMain.handler.sendMessage(msg);
				return null;
			}
		} catch (IOException e) {
			NmapError.log(e.getMessage());
			final Message msg = Message.obtain();
			msg.obj = "Unable to start shell: " + e.toString();
			msg.what = RUN_ERROR;
			NmapMain.handler.sendMessage(msg);
			return null;
		}
		if (NmapUtilities.canGetRoot && process != null)
		{
			NmapError.log("Got root!");
		}
		else if (process == null)
		{
			NmapError.log("Process p is null - did getRuntime().exec(Nmap.sh) fail?");
			final Message msg = Message.obtain();
			msg.obj = "Process for executing scan is null. Please close this program and reopen it.";
			msg.what = RUN_ERROR;
			NmapMain.handler.sendMessage(msg);
			return null;
		}
		
		outputStream = new DataOutputStream(process.getOutputStream());
		inputStream = new BufferedReader(new InputStreamReader(process.getInputStream()));
		errorStream = new BufferedReader(new InputStreamReader(process.getErrorStream()));

		if (outputStream == null)
		{
			NmapError.log("DataOutputStream 'os' is null!");
		}
		if (inputStream == null)
		{
			NmapError.log("BufferedReader 'in' is null!");
		}
		if (errorStream == null)
		{
			NmapError.log("BufferedReader 'err' is null!");
		}

		try {
			outputStream.writeBytes("cd " + bindir + "\n");
			NmapError.log("cd " + bindir);
			outputStream.flush();
			/* wtf? -h is not a special case, and you're not doing anything that different.
			 * Also, current code branching includes useless if statement.
			 */

			if ("-h".equals(exeParams))
			{
				outputStream.writeBytes("./" + command + " -h\n");
			}
			else
				if (NmapUtilities.canGetRoot)
				{
					outputStream.writeBytes("./" + command + exeParams + "\n");
					NmapError.log("./" + command + exeParams);
				}
				else
				{
					outputStream.writeBytes("./" + command + exeParams + "\n");
					NmapError.log("./" + command + exeParams);
				}

			/** @since 21 Rewrite for shorter passage that makes common fucking sense */
			/* BEGIN @since 21 */
			/*{
				if (executionParameters == null)
					executionParameters = "";
				String myCompleteCommand = "./" + command + executionParameters + "\n"; 
				os.writeBytes(myCompleteCommand);
				Nmap.ne.Log(myCompleteCommand);
			}*/
			/* END @since 21 */
			outputStream.flush();
			outputStream.writeBytes("exit\n");
			NmapError.log("exit");
			outputStream.flush();
			outputStream.close();
			
			final StringBuilder feedback = new StringBuilder();
			String error;
			int c;
			boolean outputNotEmpty = false; // Tells us the output wasn't just an empty string.
			/* Same deal as with RUN_COMPLETE_NO_FILE below - use char-based I/O.
			do
			{
				error = errorStream.readLine();
				if (error != null)
				{
					feedback.append(error);
					feedback.append('\n');
				}
			} while (error != null); */
			while ((c = errorStream.read()) != -1)
			{
				feedback.append((char) c);
				if (c != ' ' && c != '\n')
				{
					outputNotEmpty = true;
				}
			}
			error = feedback.toString();
			NmapError.log(error);

			if (error.length() > 0 && outputNotEmpty)
			{
				final Message msg1 = Message.obtain();
				msg1.obj = "Error detected at runtime: " + error;
				msg1.what = RUN_ERROR;
				NmapMain.handler.sendMessage(msg1);
				return null;
			}
		} catch (IOException e) {
			NmapError.log(e.getMessage());
			final Message msg = Message.obtain();
			msg.obj = "IOException: " + e.toString();
			msg.what = RUN_ERROR;
			NmapMain.handler.sendMessage(msg);
			return null;
		}

		try {
			final StringBuilder stringBuilder = new StringBuilder();
			// @since 29 - switch from String-based input to char based input
			String line;
			int c;
			boolean outputNotEmpty = false; // Only send the RUN_SUCCESS_NO_FILE if useful
			                                // output occurs; on empty strings/newlines send RUN_COMPLETE.
			while ((c = inputStream.read()) != -1)
			{
				stringBuilder.append((char) c);
				if (c != '\n' && c != ' ')
				{
					outputNotEmpty = true;
				}
			}
			line = stringBuilder.toString();
			if (line.length() > 0 && outputNotEmpty)
			{
				NmapError.log("Received output on stdout. Will not attempt to read -oA files.");
				final Message msg = Message.obtain();
				msg.obj = line;
				msg.what = RUN_SUCCESS_NO_FILE;
				NmapMain.handler.sendMessage(msg);
				return null;
			}
		} catch (IOException e) {
			final Message msg = Message.obtain();
			msg.obj = "Unable to read command output: " + e.toString();
			msg.what = RUN_ERROR;
			NmapMain.handler.sendMessage(msg);
			return null;
		}
		
		try {
			inputStream.close();
			errorStream.close();
		} catch (IOException e) {
			final Message msg = Message.obtain();
			msg.obj = "Unable to close IO stream: " + e.toString();
			msg.what = RUN_ERROR;
			NmapMain.handler.sendMessage(msg);
			return null;
		}

		process.destroy();

		if (!"-h".equals(exeParams)) // why is this here? Shouldn't this go even if -h specified?
		{
			final Message msg = Message.obtain();
			msg.arg1 = (int) (System.currentTimeMillis() - startTime);
			msg.what = RUN_COMPLETE;
			NmapMain.handler.sendMessage(msg);
		}
		return null;
	}
}
