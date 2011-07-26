package com.wjholden.nmap;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.StringTokenizer;

import android.content.Context;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.Message;

/**
 * Class created to centralize and more easily manage certain pieces of boilerplate
 * code, often code groups that are required more than once.
 * PMD recommended I make this a "singleton" so here goes.
 * @author William John Holden (wjholden@gmail.com)
 */
public final class NmapUtilities implements NmapConstants
{
	/**
	 * Tells us if "su" command is available.<br />
	 * Must be set by NmapUtilities.checkRootPermissions().
	 * @since 25
	 */
	public static boolean canGetRoot;
	
	/**
	 * Experimental: save the context as a private static variable, this way you
	 * need an NmapUtilities.init(Context) method, but don't need to pass
	 * context every time you run one of these variables, thereby simplifying
	 * the Scan and Install classes.
	 * @since 26
	 */
	private static Context context;
	
	/**
	 * Not used, but makes sure that only one instance of this class runs at once.
	 */
	@SuppressWarnings("unused")
	private static final NmapUtilities FINAL_INSTANCE = new NmapUtilities();
	
	/**
	 * Private constructor can only be called in the above FINAL_INSTANCE.
	 * This ensures that only one instance of this "static" class exists,
	 * hence it's a singleton.
	 */
	private NmapUtilities()
	{
		canGetRoot = false; // initialize to false, if true set in checkRootPermissions().
	}
	
	public static void init(final Context myContext)
	{
		context = myContext;
	}
	
	/**
	 * Removed from verifyInstallation for version 21.
	 * If temporary folder does not already exist, create it.<br />
	 * No longer takes Context as param. EU must init(Context) first.
	 * @since 26
	 * @throws IOException
	 * @throws NameNotFoundException
	 * @return Absolute path of the temporary folder as String.
	 */
	public static String verifyTemporaryFolder() throws IOException, NameNotFoundException
	{
		final File tmpdir = new File(context.getPackageManager().getApplicationInfo("com.wjholden.nmap", 0).dataDir + "/tmp/");
		NmapError.log("Checking if " + tmpdir.getAbsolutePath() + " exists...");
		if (tmpdir.exists())
		{
			NmapError.log(tmpdir.getAbsolutePath() + " exists.");
		}
		else
		{
			NmapError.log(tmpdir.getAbsolutePath() + " does not exist. Creating it...");
			if (tmpdir.mkdirs())
			{
				NmapError.log(tmpdir.getAbsolutePath() + " created.");
			}
			else
			{
				NmapError.log("Something went wrong - " + tmpdir.getAbsolutePath() + " could not be created.");
				
				final Message msg = Message.obtain();
				msg.obj = "Unable to create " + tmpdir.getAbsolutePath();
				msg.what = INSTALL_ERROR;
				NmapMain.handler.sendMessage(msg);
				//return null; // removing this line may introduce bugs where the program, wrongly, believes
				// that the tmpdir was successfully set when, in fact, it was not.
			}
		}
		return tmpdir.getAbsolutePath();
	}
	
	/**
	 * Mimics 'which' function to find 'su' command. Sets Nmap.sh and Nmap.canGetRoot.
	 * Originally, the program just looked for a hard-coded 'su' path, but CM6 has 'su'
	 * in a different location. Logic robusted to look everywhere in $PATH.<br />
	 * Also sets shell, using Nmap.setSh(String).<br />
	 * Since 0.5.6 also checks to see if, when <i>su</i> is found, that command can indeed
	 * be read and executed. It won't be foolproof until API9 becomes standard.
	 * @since 0.5.6
	 * @return true if su found in $PATH.
	 */
	public static String checkRootPermissions()
	{
		// should now be fixed @version 0.4.1 to allow /system/xbin/su on CM5+
		final String path = System.getenv("PATH");
		File suTest;
		boolean hasFoundRoot = false;
		final StringTokenizer pathTokens = new StringTokenizer(path, ":");
		String shell = null;

		try
		{
			while (pathTokens.hasMoreTokens() && !hasFoundRoot)
			{
				final String token = pathTokens.nextToken();
				suTest = new File(token + "/su"); // sorry PMD, I can't think of a way to do this w/o creating new objects.
				hasFoundRoot = suTest.exists();
				
				if (hasFoundRoot)
				{
					// AHHH FUCK this really doesn't work at all like I wanted. Android SDK < 9 does not implement File.canExecute(). >:(
					SecurityManager securityManager = new SecurityManager(); // rtfm on System.getSecurityManager...not implemented on Android :( 
					securityManager.checkExec(suTest.getCanonicalPath()); // if this does not throw error then we can use it.
					// The Canonical path is used to avoid problems where the symlink is executable but the file is not.
					shell = suTest.getCanonicalPath();
					NmapError.log("su command found at " + shell + "; will run with root permissions.");
				}
			}
		}
		catch (SecurityException e)
		{
			NmapError.log("Caught SecurityException: " + e.toString());
			shell = "sh";
		} catch (IOException e) {
			NmapError.log("Caught IOException (probably caused by dead symlink): " + e.toString());
			shell = "sh";
		}
		finally
		{
			if (!hasFoundRoot)
			{
				shell = "sh";
				NmapError.log("su NOT found (using " + shell + "); will run without root permissions.");
			}
			
			canGetRoot = hasFoundRoot;
		}

		return(shell);
	}
	
	/**
	 * Find the data directory to store applications in.
	 * @since 26 No params, NmapUtilities.init(Context) must be called beforehand.
	 * @return Absolute path of data directory as String.
	 */
	public static String getDataDirectory()
	{
		String dataDir = null;
		try {
			dataDir = context.getPackageManager().getApplicationInfo("com.wjholden.nmap", 0).dataDir;
		} catch (NameNotFoundException e) {
			NmapError.log(e.getMessage());
		}
		return dataDir;
	}
	
	/**
	 * Based on whether 'su' is available or not this method sets the location to write
	 * compiled binaries for later execution.
	 * @return Absolute location to write binaries as String.
	 * @since 22 - UPDATE - now ALWAYS uses the {dataDir}/bin/ folder
	 * @since 26 Removed param, calls getDataDirectory() above.
	 * @since 27 Now also create the bindir if it does not already exist here.
	 */
	public static String findBinDir()
	{
		/*if (Nmap.canGetRoot)
			Nmap.setBinDir("/data/local/bin/");
		else
			Nmap.setBinDir(myDataDir + "/bin/"); */
		
		final String bindir = getDataDirectory() + "/bin/";
		final File myBindir = new File(bindir);
		
		if (myBindir.exists())
		{
			NmapError.log(bindir + " already exists");
		}
		else
		{
			if (myBindir.mkdirs())
			{
				NmapError.log("Successfully created bindir");
			}
			else
			{
				final Message msg = Message.obtain();
				msg.obj = "Critical Error: unable to create " + bindir;
				msg.what = INSTALL_ERROR;
				NmapMain.handler.sendMessage(msg);
			}
		}
		
		NmapError.log("Set bindir to: " + bindir);
		return bindir;
	}
	
	/**
	 * A consolidated method to delete the output file after reading it in at the end of RUN_COMPLETE in NmapMain.handler.
	 * @param outputFileName String representation of the absolute path to the file.
	 * @return Whether the file was deleted or not.
	 * @since Added version 27.
	 */
	public static boolean deleteOutputFile(final String outputFileName)
	{
		final File deleteOutputFile = new File(outputFileName);
		final boolean outputFileDeleted = deleteOutputFile.delete();
		if (outputFileDeleted)
		{
			NmapError.log(outputFileName + " deleted.");
		}
		else
		{
			NmapError.log("Error: unable to delete " + outputFileName);
		}
		return outputFileDeleted;
	}
	
	/**
	 * This used to be in the RUN_COMPLETE area of NmapMain.handler.
	 * Moved here for consolidation/reusability purposes. Should help
	 * maintainability significantly.
	 * @param command Until nping and ncat are fixed this will always be 'nmap'.
	 * @param type Valid values are 'nmap', 'xml', and 'gnmap'.
	 * @return String contents of the output file (might be <i>very</i> large).
	 * @since Moved to NmapUtilties version 27.
	 */
	public static String readOutputFile(final String command, final String type)
	{
		final String outputFileName;
		final BufferedReader inputReader;
		final StringBuilder stringBuilder = new StringBuilder();;
		String line = null;
		try
		{
			outputFileName = NmapUtilities.verifyTemporaryFolder() + "/" + command + "." + type;
			inputReader = new BufferedReader(new FileReader(outputFileName));
			
			do
			{
				line = inputReader.readLine();
				if (line != null)
				{
					stringBuilder.append(line);
					stringBuilder.append('\n');
				}
			} while (line != null);
			inputReader.close();
			line = stringBuilder.toString(); // storing StringBuilder.toString() may be a micro-optimization.
			NmapError.log(line);
			NmapUtilities.deleteOutputFile(outputFileName);
		}
		catch (IOException e)
		{
			final Message msg = Message.obtain();
			msg.what = RUN_ERROR;
			msg.obj = "IOException in readOutputFile: " + e.toString();
			NmapMain.handler.sendMessage(msg);
		} catch (NameNotFoundException e) {
			final Message msg = Message.obtain();
			msg.what = RUN_ERROR;
			msg.obj = "NameNotFoundException in readOutputFile: " + e.toString();
			NmapMain.handler.sendMessage(msg);
		}
		return line;
	}
	
	/**
	 * Code slightly adapted from my previous work on 
	 * <a href="http://wjholden.com/md5/">MD5 Sums in Java</a>.<br />
	 * Does nothing if NmapMain.debug = false.
	 * <br />
	 * Presently disabled - this algorithm is painfully slow and I need to research methods
	 * for hurrying it up.
	 * 
	 * @since Version 0.4.12 (28), where <a href="http://seclists.org/nmap-dev/2011/q1/440">Vlatko announced Nmap 5.50 on Android</a>.
	 * @param filename Filename to be hashed.
	 * @param algorithm In this program, always use "MD5".
	 * @return String representation of the MD5 sum.
	 * @throws IOException Should be handled in the 'ordinary' logic of the binary write process anyways.
	 */
	public static String hashFile(final String filename, final String algorithm) throws IOException {
		MessageDigest md;
		InputStream is;
		String signature = null;
		
		if (!NmapMain.debug)
		{
			return("Hashing only enabled in debugging mode.");
		}
		
		if (NmapMain.debug)
		{
			return("Hashing temporarily disabled completely.");
		}
		
		try {
			md = MessageDigest.getInstance(algorithm);
			is = new FileInputStream(filename);
			is = new DigestInputStream(is, md);
			while (is.read() != -1)
				;
			is.close();
			signature = new BigInteger(1, md.digest()).toString(16);
			while (signature.length() < 32) {
				signature = "0" + signature;
			}
			NmapError.log(filename + ": " + algorithm + " hash = " + signature);
		} catch (NoSuchAlgorithmException e) {
			NmapError.log("Unexpected NoSuchAlgorithmException: " + e.toString());
		}
		return (signature);
	}
}
