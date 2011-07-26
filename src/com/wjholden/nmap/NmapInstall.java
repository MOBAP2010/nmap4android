package com.wjholden.nmap;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;

import android.content.Context;
import android.content.res.Resources;
import android.os.AsyncTask;
import android.os.Message;

/**
 * Verifies the installation of Nmap binaries asynchronously.
 * Checks whether root permissions are available or not (Nmap.canGetRoot).
 * Creates the binary directory (Nmap.bindir).
 * <br>
 * TODO: Use md5 sums of files to ensure integrity.
 * 
 * @author William John Holden (wjholden@gmail.com)
 */
public class NmapInstall extends AsyncTask <Object, Void, Void> implements NmapConstants
{
	/**
	 * Once you have the application Context, use that to establish a Resources object that can be used to open
	 * the R.raw.* files.
	 */
	private transient Resources resources;
	
	private transient Context context;

	/**
	 * If the second parameter sent to new NmapInstall(Context, String) is "restart" then
	 * NmapInstall will send a message to NmapMain.handler telling it to restart the app
	 * after install completes.
	 */
	private transient boolean forceRestart;
	
	private transient String bindir;
	
	protected void onPostExecute(final Void myVoid)
	{
		NmapMain.progressDialog.dismiss();
		NmapMain.installVerified = true;
		
		if (forceRestart)
		{
			NmapMain.handler.sendEmptyMessage(FORCE_RESTART);
		}
	}

	@Override
	protected Void doInBackground(final Object... params)
	{
		forceRestart = params[0].equals("restart");
		context = (Context) params[1];
		resources = context.getResources();
		
		bindir = NmapUtilities.findBinDir();

		try
		{
			//writeNmap_5_30BETA1();
			writeNmapSvn();
			writeNmapAtrix();
			/*if (writeNmapSvn())
			{
				NmapError.log("Good install of Nmap 5.50.");
			}
			else
			{
				NmapError.log("Nmap 5.50 failed MD5 verification.");
			}
			writeNcat();*/
			writeNmapServiceProbes();
			writeNmapOsDb();
			for (int k = 0; k < INSTALL_RESOURCES.length; k++)
			{
				writeOthers(INSTALL_FILENAMES[k], INSTALL_RESOURCES[k]);
			}
			setPermissions();
			NmapMain.handler.sendEmptyMessage(INSTALL_GOOD);
		}
		catch (IOException e)
		{
			final Message msg = Message.obtain();
			msg.obj = "Installation error: " + e.toString();
			msg.what = INSTALL_ERROR;
			NmapMain.handler.sendMessage(msg);
		} catch (InterruptedException e) {
			final Message msg = Message.obtain();
			msg.obj = e.toString();
			msg.what = INSTALL_ERROR;
			NmapMain.handler.sendMessage(msg);
		}
		
		return null;
	}
	
	/**
	 * Simple method for deleting a file if it does not exist.
	 * Note there could be a bug here - if the expected behavior
	 * was to /create/ the file, then this is always creating a file,
	 * then deleting it. Seems a little backward.
	 * @param path
	 */
	private void createNewFileAndDeleteExisting(final String path)
	{
		final File myFile = new File (path);
		if (myFile.exists())
		{
			NmapError.log(path + " already exists. Deleting...");
			if (myFile.delete())
			{
				NmapError.log("\tdeleted.");
			}
			else
			{
				NmapError.log("\tunable to delete.");
			}
		}
	}
		
	/**
	 * Writes the Nmap binary to filesystem as provided in the
	 * R.raw.nmap_a-c resources.<br>
	 * Uses whatever Nmap.bindir as the location to write nmap.
	 * @throws IOException
	 */
	/*
	private void writeNmap_5_30BETA1() throws IOException
	{
		final byte[] buf = new byte[BUFFER_SIZE];
		final String filename = bindir + "/nmap_5_30_BETA1";
		createNewFileAndDeleteExisting(filename);
		
		final InputStream in_nmap_a = resources.openRawResource(R.raw.nmap_a);
		final InputStream in_nmap_b = resources.openRawResource(R.raw.nmap_b);
		final InputStream in_nmap_c = resources.openRawResource(R.raw.nmap_c);
		final OutputStream out_nmap = new FileOutputStream(filename);
		while (in_nmap_a.read(buf) > 0)
		{
			out_nmap.write(buf);
		}
		in_nmap_a.close();
		while (in_nmap_b.read(buf) > 0)
		{
			out_nmap.write(buf);
		}
		in_nmap_b.close();
		while (in_nmap_c.read(buf) > 0)
		{
			out_nmap.write(buf);
		}
		in_nmap_c.close();
		out_nmap.close();
	}
	*/
	
	private boolean writeNmapSvn() throws IOException
	{
		final byte[] buf = new byte[BUFFER_SIZE];
		final String filename = bindir + "nmap";
		//final String hash;
		createNewFileAndDeleteExisting(filename);
		
		final InputStream in_nmap_aa = resources.openRawResource(R.raw.nmap_aa);
		final InputStream in_nmap_ab = resources.openRawResource(R.raw.nmap_ab);
		final InputStream in_nmap_ac = resources.openRawResource(R.raw.nmap_ac);
		final InputStream in_nmap_ad = resources.openRawResource(R.raw.nmap_ad);
		final InputStream in_nmap_ae = resources.openRawResource(R.raw.nmap_ae);
		final InputStream in_nmap_af = resources.openRawResource(R.raw.nmap_af);
		final InputStream in_nmap_ag = resources.openRawResource(R.raw.nmap_ag);
		final OutputStream out_nmap = new FileOutputStream(filename);
		while (in_nmap_aa.read(buf) > 0)
		{
			out_nmap.write(buf);
		}
		in_nmap_aa.close();
		while (in_nmap_ab.read(buf) > 0)
		{
			out_nmap.write(buf);
		}
		in_nmap_ab.close();
		while (in_nmap_ac.read(buf) > 0)
		{
			out_nmap.write(buf);
		}
		in_nmap_ac.close();
		while (in_nmap_ad.read(buf) > 0)
		{
			out_nmap.write(buf);
		}
		in_nmap_ad.close();
		while (in_nmap_ae.read(buf) > 0)
		{
			out_nmap.write(buf);
		}
		in_nmap_ae.close();
		while (in_nmap_af.read(buf) > 0)
		{
			out_nmap.write(buf);
		}
		in_nmap_af.close();
		while (in_nmap_ag.read(buf) > 0)
		{
			out_nmap.write(buf);
		}
		in_nmap_ag.close();
		out_nmap.close();
		//hash = context.getString(R.string.nmap_5_50_md5);
		//return hash.equals(NmapUtilities.hashFile(filename, "MD5"));
		
		return true;
	}
	
	private boolean writeNmapAtrix() throws IOException
	{
		final byte[] buf = new byte[BUFFER_SIZE];
		final String filename = bindir + "nmap_atrix";
		//final String hash;
		createNewFileAndDeleteExisting(filename);
		
		final InputStream in_nmap_aa = resources.openRawResource(R.raw.nmap_atrix_aa);
		final InputStream in_nmap_ab = resources.openRawResource(R.raw.nmap_atrix_ab);
		final InputStream in_nmap_ac = resources.openRawResource(R.raw.nmap_atrix_ac);
		final InputStream in_nmap_ad = resources.openRawResource(R.raw.nmap_atrix_ad);
		final InputStream in_nmap_ae = resources.openRawResource(R.raw.nmap_atrix_ae);
		final InputStream in_nmap_af = resources.openRawResource(R.raw.nmap_atrix_af);
		final InputStream in_nmap_ag = resources.openRawResource(R.raw.nmap_atrix_ag);
		final OutputStream out_nmap = new FileOutputStream(filename);
		while (in_nmap_aa.read(buf) > 0)
		{
			out_nmap.write(buf);
		}
		in_nmap_aa.close();
		while (in_nmap_ab.read(buf) > 0)
		{
			out_nmap.write(buf);
		}
		in_nmap_ab.close();
		while (in_nmap_ac.read(buf) > 0)
		{
			out_nmap.write(buf);
		}
		in_nmap_ac.close();
		while (in_nmap_ad.read(buf) > 0)
		{
			out_nmap.write(buf);
		}
		in_nmap_ad.close();
		while (in_nmap_ae.read(buf) > 0)
		{
			out_nmap.write(buf);
		}
		in_nmap_ae.close();
		while (in_nmap_af.read(buf) > 0)
		{
			out_nmap.write(buf);
		}
		in_nmap_af.close();
		while (in_nmap_ag.read(buf) > 0)
		{
			out_nmap.write(buf);
		}
		in_nmap_ag.close();
		out_nmap.close();
		//hash = context.getString(R.string.nmap_5_50_md5);
		//return hash.equals(NmapUtilities.hashFile(filename, "MD5"));
		
		return true;
	}
	
	/**
	 * Write the Ncat file to disk.
	 * @throws IOException
	 */
	/*private void writeNcat() throws IOException
	{
		final byte[] buf = new byte[BUFFER_SIZE];
		createNewFileAndDeleteExisting(bindir + "/ncat");
		
		final InputStream in_ncat_a = resources.openRawResource(R.raw.ncat_a);
		final InputStream in_ncat_b = resources.openRawResource(R.raw.ncat_b);
		final OutputStream out = new FileOutputStream(bindir + "/ncat");
		while (in_ncat_a.read(buf) > 0)
		{
			out.write(buf);
		}
		in_ncat_a.close();
		while (in_ncat_b.read(buf) > 0)
		{
			out.write(buf);
		}
		in_ncat_b.close();
		out.close();
	}*/
	
	/**
	 * Write the nmap-os-db file to disk.
	 * @throws IOException
	 */
	private void writeNmapOsDb() throws IOException
	{
		final byte[] buf = new byte[BUFFER_SIZE];
		createNewFileAndDeleteExisting(bindir + "nmap-os-db");
		
		final InputStream in_nmaposdb_aa = resources.openRawResource(R.raw.nmap_os_db_aa);
		final InputStream in_nmaposdb_ab = resources.openRawResource(R.raw.nmap_os_db_ab);
		final InputStream in_nmaposdb_ac = resources.openRawResource(R.raw.nmap_os_db_ac);
		final OutputStream out = new FileOutputStream(bindir + "/nmap-os-db");
		while (in_nmaposdb_aa.read(buf) > 0)
		{
			out.write(buf);
		}
		in_nmaposdb_aa.close();
		while (in_nmaposdb_ab.read(buf) > 0)
		{
			out.write(buf);
		}
		in_nmaposdb_ab.close();
		while (in_nmaposdb_ac.read(buf) > 0)
		{
			out.write(buf);
		}
		in_nmaposdb_ac.close();
		out.close();
	}
	
	/**
	 * Write the nmap-service-probes file to disk.
	 * @throws IOException
	 */
	private void writeNmapServiceProbes() throws IOException
	{
		final byte[] buf = new byte[BUFFER_SIZE];
		createNewFileAndDeleteExisting(bindir + "nmap-service-probes");
		
		final InputStream in_nmapsp_aa = resources.openRawResource(R.raw.nmap_service_probes_aa);
		final InputStream in_nmapsp_ab = resources.openRawResource(R.raw.nmap_service_probes_ab);
		final OutputStream out = new FileOutputStream(bindir + "/nmap-service-probes");
		while (in_nmapsp_aa.read(buf) > 0)
		{
			out.write(buf);
		}
		in_nmapsp_aa.close();
		while (in_nmapsp_ab.read(buf) > 0)
		{
			out.write(buf);
		}
		in_nmapsp_ab.close();
		out.close();
	}
	
	/**
	 * Write the other files to disk.
	 * @param filename Filename that corresponds with the resource.
	 * @param resource Resource in R.raw.*.
	 * @throws IOException
	 */
	private void writeOthers(final String filename, final int resource) throws IOException
	{
		final byte[] buf = new byte[BUFFER_SIZE];
		createNewFileAndDeleteExisting(bindir + filename);
		
		final InputStream in1 = resources.openRawResource(resource);
		final OutputStream out = new FileOutputStream(bindir + "/" + filename);
		while (in1.read(buf) > 0)
		{
			out.write(buf);
		}
		in1.close();
		out.close();
	}
	
	/**
	 * Uses CHMOD and CHOWN to set permissions based on NmapMain.canGetRoot.
	 * @throws IOException
	 * @throws InterruptedException
	 */
	private void setPermissions() throws IOException, InterruptedException
	{
		String shell;
		String installResult;
		//java.io.File file_nmap = new java.io.File(Nmap.bindir + "/nmap");
		//file_nmap.setExecutable(true); // not implemented? WTF?!!!
		                                 // RTFM it's API9+ only.
		                                 // Android API8- ~= Sun JRE 1.4.2
		                                 // Android API9+ ~= JRE6
		
		shell = NmapUtilities.checkRootPermissions();
		
		final Process process = NmapUtilities.canGetRoot ? Runtime.getRuntime().exec(shell) :  Runtime.getRuntime().exec(shell);
		final DataOutputStream outputStream = new DataOutputStream(process.getOutputStream());
		final BufferedReader inputStream = new BufferedReader(new InputStreamReader(process.getInputStream()), BUFFER_SIZE);
		final BufferedReader errorStream = new BufferedReader(new InputStreamReader(process.getErrorStream()), BUFFER_SIZE);
		outputStream.writeBytes("cd " + bindir + "\n");
		
		if (NmapUtilities.canGetRoot)
		{
			outputStream.writeBytes("chown root.root *\n");
			NmapError.log("chown root.root *");
		}
		outputStream.writeBytes("chmod 555 *\n");
		NmapError.log("chmod 555 *\n");
		
		outputStream.writeBytes("chmod 777 " + NmapUtilities.findBinDir() + "\n");
		NmapError.log("chmod 777 " + NmapUtilities.findBinDir() + "\n");
		
		outputStream.writeBytes("exit\n");
		NmapError.log("exit");
		
		final StringBuilder feedback = new StringBuilder();
		String input, error;
		do
		{
			input = inputStream.readLine();
			if (input != null) // StringBuilder.append(String) will append the word 'null' if String == null so
			{                  // we need this check to prevent the machine from wrongly believing errors occurred.
				feedback.append(input);
			}
		} while (input != null);
		do
		{
			error = errorStream.readLine();
			if (error != null)
			{
				feedback.append(error);
			}
		} while (error != null);
		
		installResult = feedback.toString();
		NmapError.log(installResult);
		
		outputStream.close();
		inputStream.close();
		errorStream.close();
		process.waitFor();
		process.destroy();
		
		if (installResult.length() > 0)
		//if (installationResults != null && !installationResults.equals(""))
		{
			final Message msg = Message.obtain();
			msg.obj = installResult;
			msg.what = INSTALL_ERROR;
			NmapMain.handler.sendMessage(msg);
		}
	}
}
