/**
 * TODO
 * <ul>
 * 	<li>Options Activity, with 'force no root' option, toggle logcat</li>
 * 	<li>nmap-mac-prefixes auto updater</li>
 * 	<li>GPL dialog</li>
 * </ul>
 */
package com.wjholden.nmap;

import java.io.File;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager.NameNotFoundException;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.preference.PreferenceManager;
import android.provider.Settings;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import com.android.vending.licensing.AESObfuscator;
import com.android.vending.licensing.LicenseChecker;
import com.android.vending.licensing.LicenseCheckerCallback;
import com.android.vending.licensing.ServerManagedPolicy;

/**
 * <a href="http://nmap.wjholden.com">Nmap for Android!</a>
 * The original versions used Nmap binaries I got from Robert McCurdy (http://rmccurdy.com/stuff/G1/BINS/NMAP/).
 * Around v0.3 or Vlatko Kosturjak build newer binaries based on Nmap 5.3 (http://ftp.linux.hr/android/nmap/).
 * @author William John Holden (wjholden@gmail.com)
 * @version 0.4.7
 */
public class NmapMain extends Activity implements NmapConstants {
	/**
	 * Text area where results are shown.<br />
	 * TODO: looks like Intent ACTION_VIEW has a neat feature to view a URL -
	 * would it be possible to create a URL based on a String, then view this value in fullscreen?
	 */
	private transient TextView mResults;
	
	/**
	 * Input area where command-line arguments (other than target IP)
	 */
	private transient EditText mArguments;
	
	/**
	 * Input area where user supplies scan target
	 */
	private transient EditText mTarget;
	
	/**
	 * Start button initiates scan 
	 */
	private transient Button mStart;
	
	/**
	 * Launch NmapSubnet activity.
	 */
	private transient Button mSubnet;
	
	/**
	 * Help button, shows result of [command] --help
	 */
	private transient Button mHelp;
	
	/**
	 * Share button, launches Compose Email activity with message body of any data in mResults
	 */
	private transient Button mShare;
	
	/**
	 * Command spinner switches between Nmap, Nping, and Ncat
	 */
	private transient Spinner mCommandSpinner;
	
	/**
	 * Switches between Nmap, XML, and Grepable Nmap output
	 */
	private transient Spinner mOutputSpinner;

	/**
	 * if "VerifyInstallation()" method has run this should be set to true
	 * @since 0.4.2
	 * This and most other static variables here are saved in SharedPreferences so verifyInstallation
	 * only runs once.
	 */
	public static boolean installVerified;
	
	/**
	 * tells us whether one or more scans have been executed
	 */
	public static boolean hasRunOneScan;
	
	/**
	 * this is where the nmap/nping/ncat compiled binaries should be stored.
	 * @deprecated
	 */
	@Deprecated
	public static String bindir;
	
	/**
	 * Location of the 'su' command, if present, otherwise 'sh'.<br />
	 * Use local variables instead of this. Will be removed entirely soon.
	 * @since 25 Must be set by NmapUtiltiies.checkRootPermissions().
	 * @deprecated
	 */
	@Deprecated
	public static String shellCmdLoc;
	
	/**
	 * the command to be executed (nmap, nping, ncat) and optional (and mandatory) command line arguments from mArguments.<br />
	 * Use local vars in NmapScan instead of this. This variable is causing bugs.
	 * @deprecated
	 */
	@Deprecated
	public static String outputArgs;

	/**
	 * tells the scanning engine what command is to be executed (nmap, nping, ncat)
	 */
	public static int scanType;
	
	/**
	 * verify installation thread
	 */
	private transient AsyncTask<Object, Void, Void> installTask = null;
	
	/**
	 * scanning engine thread
	 */
	private transient AsyncTask<String,Void,Void> scanTask = null;
	
	/**
	 * handler for inter-thread communication
	 */
	public static Handler handler;
	
	/**
	 * Static so that the other classes can turn it off after it runs.
	 * This shall be the only ProgressDialog used. Don't use "new" - instead just change the text
	 * and show/hide it.
	 */
	public static ProgressDialog progressDialog;
	
	/**
	 * Store both user and application settings in here.
	 */
	private transient SharedPreferences settings;
	
	/**
	 * This variable is set by the user with the context menu.
	 * If on, use the Log utility to send debugging information to
	 * logcat, and also present user with a menu option to e-mail
	 * debugging output to developer.
	 */
	public static boolean debug;
	
	/**
	 * After reinstalling binaries, wipe the preferences.
	 */
	private boolean deletePreferences = false;
	
	/**
	 * Instead of keeping old output on the filesystem, read it in and out as a String kept in memory.
	 * This is for normal output.
	 * @since Added in version 27.
	 */
	private transient String outputNmap;
	
	/**
	 * Instead of keeping old output on the filesystem, read it in and out as a String kept in memory.
	 * This is for XML output.
	 * @since Added in version 27.
	 */
	private transient String outputXml;
	
	/**
	 * Instance of thread where NmapWifi executes.
	 */
	private transient NmapWifi wifi;
	
	/**
	 * Instead of keeping old output on the filesystem, read it in and out as a String kept in memory.
	 * This is for Nmap grepable output.
	 * @since Added in version 27.
	 */
	private transient String outputGrep;
	
	/**
	 * See <a href="http://developer.android.com/guide/publishing/licensing.html">Android Developers
	 * Guide</a> for details on usage of License Verification Library.
	 */
	private LicenseCheckerCallback mLicenseCheckerCallback;
	
	/**
	 * See <a href="http://developer.android.com/guide/publishing/licensing.html">Android Developers
	 * Guide</a> for details on usage of License Verification Library.
	 */
	private LicenseChecker mChecker;
	
	/**
	 * Basic <a href="http://developer.android.com/guide/topics/ui/notifiers/notifications.html">NotificationManager</a>
	 * for showing status bar notifications that the scan is in-progress
	 * or completed.
	 */
	private NotificationManager notificationManager;

	@Override
	public void onCreate(final Bundle bundle) {
		super.onCreate(bundle);
		setContentView(R.layout.main);

		//Debug.startMethodTracing("nmap");
		
		NmapUtilities.init(getApplicationContext());
		initScreen();
		initVariables();
		initSpinners();
		initHandler();
		initBindir();
		//showWifiInfo(); -- moved into NmapWifi.java
		showApkInfo();
		initButtons();
		
		mLicenseCheckerCallback = new MyLicenseCheckerCallback();
		
		mChecker = new LicenseChecker(
				this, new ServerManagedPolicy(this,
						new AESObfuscator(SALT, getPackageName(), Settings.Secure.ANDROID_ID)),
						BASE64_PUBLIC_KEY
						);
		
		mChecker.checkAccess(mLicenseCheckerCallback);
		
		if (!installVerified && (installTask == null || installTask.getStatus() == AsyncTask.Status.FINISHED || installTask.getStatus() == AsyncTask.Status.RUNNING))
		{
			progressDialog = new ProgressDialog(this);
			progressDialog.setMessage("Verifying installation. Select \"Allow\" if prompted.");
			progressDialog.show();
			installTask = new NmapInstall().execute("norestart", this.getApplicationContext());
		}
		
		wifi = new NmapWifi(this.getApplicationContext());
		wifi.start();
	}
	
	@Override
	protected void onDestroy() {
		notificationManager.cancelAll();
		//Debug.stopMethodTracing();
		NmapWifi.closing = true;
		
		if (installTask != null)
		{
			installTask.cancel(true);
		}
		if (scanTask != null)
		{
			scanTask.cancel(true);
		}
		saveUserEntry();
		super.onDestroy();
		mChecker.onDestroy();
	}

	protected void onResume(final Bundle bundle) {
		super.onRestoreInstanceState(bundle);
		installVerified = bundle.getBoolean("installVerified");
		hasRunOneScan = bundle.getBoolean("hasRunOneScan");
		//bindir = bundle.getString("bindir");
		outputNmap = bundle.getString("outputNmap");
		outputXml = bundle.getString("outputXml");
		outputGrep = bundle.getString("outputGrep");
		/* Removed version 26 bugfix migrate outputArgs to NmapScan class as transient.
		outputArgs = bundle.getString("outputArgs"); */
		if (installTask != null)
		{
			installTask.cancel(true);
		}
		if (scanTask != null)
		{
			scanTask.cancel(true);
		}
		
		if (wifi == null)
		{
			wifi = new NmapWifi(this.getApplicationContext());
			wifi.start();
		}
	}

	protected void onPause(final Bundle outState) {
		saveUserEntry();
		
		NmapWifi.closing = true;
		wifi = null;
		
		Looper.myLooper().quit();
		outState.putBoolean("installVerified", installVerified);
		outState.putBoolean("hasRunOneScan", hasRunOneScan);
		//outState.putString("bindir", bindir);
		outState.putString("outputNmap", outputNmap);
		outState.putString("outputXml", outputXml);
		outState.putString("outputGrep", outputGrep);
		/* Removed version 26 bugfix migrate outputArgs to NmapScan class as transient.
		outState.putString("outputArgs", outputArgs); */
		super.onSaveInstanceState(outState);
	}
	
	/**
	 * Saves user preferences using the SharedPreferences.Editor
	 * object. The actual settings are stored in an XML file within the
	 * application context.
	 * Checks deletePreferences variable to wipe preferences when user
	 * forces reinstallation.
	 */
	private void saveUserEntry()
	{
		final SharedPreferences.Editor preferencesEditor = settings.edit();
		if (deletePreferences)
		{
			preferencesEditor.clear();
		}
		else
		{
			preferencesEditor.putString("target", mTarget.getText().toString());
			preferencesEditor.putString("args", mArguments.getText().toString());
			preferencesEditor.putString("result", mResults.getText().toString());
			preferencesEditor.putString("outputNmap", outputNmap);
			preferencesEditor.putString("outputXml", outputXml);
			preferencesEditor.putString("outputGrep", outputGrep);
			preferencesEditor.putBoolean("DEBUG", debug);
			
			int currentVersion = 0;
			try {
				currentVersion = getPackageManager().getPackageInfo("com.wjholden.nmap", 0).versionCode;
			} catch (NameNotFoundException e) {
				NmapError.log("Unable to get version number: " + e.toString());
			}
			preferencesEditor.putInt("versionLastRun", currentVersion);
			
			preferencesEditor.putBoolean("installVerified", installVerified);
			preferencesEditor.putBoolean("hasRunOneScan", hasRunOneScan);
			// remove outputArgs @since 21
			//preferencesEditor.putString("outputArgs", outputArgs);
		}
		preferencesEditor.commit();
	}

	@Override
	public boolean onPrepareOptionsMenu(final Menu menu) {
		menu.removeGroup(MG_DEBUG);
		menu.removeGroup(MG_DEFAULT);
		if (NmapMain.debug)
		{
			menu.add(MG_DEBUG, MI_DEBUG_ENABLE, Menu.NONE, "Disable Debugging");
			menu.add(MG_DEBUG, MI_DEBUG_EMAIL, Menu.NONE, "Error Reporting");
		}
		else
		{
			menu.add(MG_DEBUG, MI_DEBUG_ENABLE, Menu.NONE, "Enable Debugging");
		}
		
		//menu.add(MG_DEFAULT, MI_SUBNET, Menu.NONE, "Subnet Info");
		//menu.add(MG_DEBUG, MI_SURVEY, Menu.NONE, "Survey"); // removed in version 30 - few contributed and it's no longer relevant.
		menu.add(MG_DEFAULT, MI_MORE_HELP, Menu.NONE, "More help on the web");
		menu.add(MG_DEFAULT, MI_REINSTALL, Menu.NONE, "Reinstall");
		//menu.add(MG_DEFAULT, MI_ADVANCED, Menu.NONE, "Advanced Options");
		menu.add(MG_DEFAULT, MI_EXIT, Menu.NONE, "Exit");
		return super.onCreateOptionsMenu(menu);
	}

	@Override
	public boolean onMenuItemSelected(final int featureId, final MenuItem item) {
		switch (item.getItemId())
		{
		case MI_DEBUG_ENABLE:
			NmapMain.debug ^= true;
			break;
		case MI_DEBUG_EMAIL:
			final Intent emailIntent = new Intent(android.content.Intent.ACTION_SEND);
			emailIntent.setType("plain/text");
			emailIntent.putExtra(android.content.Intent.EXTRA_SUBJECT, "Nmap Debugging Output");
			emailIntent.putExtra(android.content.Intent.EXTRA_TEXT, NmapError.getLog());
			emailIntent.putExtra(android.content.Intent.EXTRA_EMAIL, new String[] { "wjholden@gmail.com" });
			NmapMain.this.startActivity(emailIntent);
			break;
		case MI_MORE_HELP:
			final Uri uri = Uri.parse( "http://nmap.org/book/man.html" );
			startActivity( new Intent( Intent.ACTION_VIEW, uri ) );
			break;
		case MI_EXIT:
			this.finish();
			break;
		case MI_REINSTALL:
			progressDialog = new ProgressDialog(this);
			progressDialog.setMessage("Verifying installation. Select \"Allow\" if prompted.");
			progressDialog.show();
			installTask = new NmapInstall().execute("restart", this.getApplicationContext());
			break;
		/*case MI_SURVEY:
			NmapError.log("Showing 'Survey' Activity.");
			final Intent surveyActivity = new Intent(NmapMain.this, NmapSurvey.class);
			startActivity(surveyActivity);
			break;*/
		case MI_ADVANCED:
			// not yet implemented
			break;
		/*case MI_SUBNET:
			NmapError.log("Showing 'Subnet' Activity.");
			final Intent subnetActivity = new Intent(NmapMain.this, NmapSubnet.class);
			startActivity(subnetActivity);
			break;*/
		default:
			NmapError.log("Somehow got the 'default' option in onMenuItemSelected.");
			break;
		}
		return super.onMenuItemSelected(featureId, item);
	}
	
	/**
	 * Use the Settings object to grab program variables from XML and set them appropriately.
	 */
	private void initVariables()
	{
		settings = PreferenceManager.getDefaultSharedPreferences(this.getApplicationContext());
		
		debug = settings.getBoolean("DEBUG", false);
		
		final String target = settings.getString("target", ""); // originally ("target", null)
		NmapError.log("target = " + target);
		/** @since 22 - just set target = "" if not in settings...hints should work for "" */
		//if (target != null && !target.equals("")) // these checks are to enable hints for new users 
		mTarget.setText(target);
		final String args = settings.getString("args", ""); // originally ("args", null)
		NmapError.log("args = " + args);
		/** @since 22 same as above */
		//if (args != null && !args.equals(""))
		mArguments.setText(args);
		/** @since 22 moved license notice to res/values/strings.xml */
		final String resultText = settings.getString("result", getString(R.string.gpl));
		mResults.setText(resultText);
		
		int lastVersionRun = settings.getInt("versionLastRun", -1);
		int currentVersion = 0;
		try {
			currentVersion = getPackageManager().getPackageInfo("com.wjholden.nmap", 0).versionCode;
		} catch (NameNotFoundException e) {
			NmapError.log("Unable to get version number: " + e.toString());
		}
		
		installVerified = settings.getBoolean("installVerified", false);
		NmapError.log("installVerified = " + installVerified);
		if (installVerified && (currentVersion != lastVersionRun)) // force install verification process each time user upgrades.
		{
			installVerified = false;
		}
		hasRunOneScan = settings.getBoolean("hasRunOneScan", false);
		NmapError.log("hasRunOneScan = " + hasRunOneScan);
		
		outputNmap = settings.getString("outputNmap", null);
		outputXml = settings.getString("outputXml", null);
		outputGrep = settings.getString("outputGrep", null);
		
		/* shellCmdLoc and canGetRoot are both set in NmapUtilities.checkRootPermissions()
		 * Removed completely in version 27. 
		shellCmdLoc = NmapUtilities.checkRootPermissions();
		NmapError.log("sh = " + shellCmdLoc);*/
		
		notificationManager = initNotificationManager();
	}
	
	/**
	 * As of version 27 do not use this, instead allow NmapScan and NmapInstall
	 * to call similar functionality augmented to NmapUtilities.findBinDir().
	 * @deprecated
	 */
	@Deprecated
	private void initBindir()
	{
		/** @since 22 bindir is no longer a setting and is generated at runtime every execution for safety
		 * This may end up being an expensive call but I think it's worth it for reliability */
		bindir = NmapUtilities.findBinDir();
		
		final File myBindir = new File(bindir);
		NmapError.log("bindir = " + bindir);
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
		
		/** @since 21 - do NOT put outputArgs into SharedPreference! It broke the whole thing earlier. */
		/** @since 22 - use the SD Card instead of the ../tmp/ folder...this should make it good */
		/** @since 22 - move this into the scan class as it needs to be different for different programs */
		//Nmap.outputArgs = new String(" -oA " + "/sdcard/" + mCommandSpinner.getSelectedItem().toString() + " ");
	}
	
	/**
	 * AFTER initScreen() has been called, assign callbacks to buttons.
	 */
	private void initButtons()
	{
		mStart.setEnabled(false);
		mStart.setOnClickListener(new View.OnClickListener() {

			@Override
			public void onClick(final View myView) {
				//scanType = mCommandSpinner.getSelectedItemPosition() + SCANTYPE_NMAP;

				mResults.setText("");
				
				// Version 28 - reversed to arguments, then target.
				final String targetAndArgs = mArguments.getText().toString() + " " + mTarget.getText().toString();
				/*if (targetAndArguments == null || targetAndArguments.length() == 0)
					targetAndArguments = "";*/
				if (scanTask == null || scanTask.getStatus() == AsyncTask.Status.FINISHED || scanTask.getStatus() == AsyncTask.Status.RUNNING)
				{
					mStart.setText("Abort");
					progressDialog = new ProgressDialog(NmapMain.this);
					progressDialog.setMessage("Please wait...");
					progressDialog.show();
					scanTask = new NmapScan().execute(targetAndArgs);
					if (NmapMain.debug)
					{
						NmapError.log("Starting scan with the following values:");
						NmapError.log("\t" + targetAndArgs);
					}
				}
				else
				{
					if (!scanTask.cancel(false))
					{
						handler.sendEmptyMessage(THREAD_ERROR);
					}
				}
			}
		});

		mHelp.setOnClickListener(new View.OnClickListener() {

			@Override
			public void onClick(final View myView) {
				//scanType = mCommandSpinner.getSelectedItemPosition() + SCANTYPE_NMAP;
				progressDialog = new ProgressDialog(NmapMain.this);
				progressDialog.setMessage("Press your menu button to get even more documentation.");
				progressDialog.show();
				
				mResults.setText("");
				if (scanTask == null || scanTask.getStatus() == AsyncTask.Status.FINISHED || scanTask.getStatus() == AsyncTask.Status.RUNNING)
				{
					scanTask = new NmapScan().execute("-h");
				}
				else
				{
					if (!scanTask.cancel(false))
					{
						handler.sendEmptyMessage(THREAD_ERROR);
					}
				}
			}
		});

		mShare.setOnClickListener(new View.OnClickListener() {

			@Override
			public void onClick(final View myView) {
				final Intent emailIntent = new Intent(android.content.Intent.ACTION_SEND);
				emailIntent.setType("plain/text");
				emailIntent.putExtra(android.content.Intent.EXTRA_SUBJECT, "Nmap Scan Results");
				emailIntent.putExtra(android.content.Intent.EXTRA_TEXT, mResults.getText().toString());
				NmapMain.this.startActivity(emailIntent);
			}
		});
		
		mSubnet.setOnClickListener(new View.OnClickListener() {
			
			@Override
			public void onClick(View v) {
				NmapError.log("Showing 'Subnet' Activity.");
				final Intent subnetActivity = new Intent(NmapMain.this, NmapSubnet.class);
				startActivity(subnetActivity);
			}
		});
	}
	
	/**
	 * Maps the buttons, text areas, and spinners to program variables.
	 */
	private void initScreen()
	{
		mResults = (TextView) findViewById(R.id.results);
		mArguments = (EditText) findViewById(R.id.Arguments);
		mTarget = (EditText) findViewById(R.id.Target);
		mStart = (Button) findViewById(R.id.Start);
		mHelp = (Button) findViewById(R.id.Help);
		mShare = (Button) findViewById(R.id.Share);
		mSubnet = (Button) findViewById(R.id.SubnetButton);
	}
	
	/**
	 * Initializes the spinners.
	 * Separated from initScreen() due to circular dependencies.
	 * @since Added version 27.
	 */
	private void initSpinners()
	{
		mCommandSpinner = (Spinner) findViewById(R.id.CommandSpinner);
		final ArrayAdapter<CharSequence> adapterCommand = ArrayAdapter.createFromResource(
				this, R.array.commands, android.R.layout.simple_spinner_item);
		adapterCommand.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		mCommandSpinner.setAdapter(adapterCommand);

		mCommandSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {

			@Override
			public void onItemSelected(final AdapterView<?> arg0, final View arg1,
					final int arg2, final long arg3) {
				//scanType = mCommandSpinner.getSelectedItemPosition() + SCANTYPE_NMAP;
				// this code, while admitantly brilliant, may be confusing enough to introduce maintenance problems
				// later when I 
				scanType = mCommandSpinner.getSelectedItemPosition() + SCANTYPE_NMAP_SVN;

				/*if (mCommandSpinner.getSelectedItem().toString().equals("nmap") && !mArguments.getText().toString().contains("--system-dns"))
					mArguments.setText("--system-dns " + mArguments.getText().toString()); */

				NmapError.log(mCommandSpinner.getSelectedItem().toString() + " selected.");
			}

			@Override
			public void onNothingSelected(final AdapterView<?> arg0) {
				NmapError.log("Nothing was selected in mCommandSpinner.");
			}});
		
		mOutputSpinner = (Spinner) findViewById(R.id.OutputSpinner);
		final ArrayAdapter<CharSequence> adapterOutput = ArrayAdapter.createFromResource(
				this, R.array.output, android.R.layout.simple_spinner_item);
		adapterOutput.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		mOutputSpinner.setAdapter(adapterOutput);
		
		mOutputSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {

			@Override
			public void onItemSelected(AdapterView<?> arg0, View arg1,
					int position, long arg3) {
				/* version 27 - why is this here? I understand what it does, but why here?
				if (hasRunOneScan && installVerified)
				{					
					mResults.setText("");
					handler.sendEmptyMessage(RUN_COMPLETE);
				}
				*/
				switch (position)
				{
				case 0:
					if (outputNmap != null)
					{
						mResults.setText(outputNmap);
					}
					break;
				case 1:
					if (outputXml != null)
					{
						mResults.setText(outputXml);
					}
					break;
				case 2:
					if (outputGrep != null)
					{
						mResults.setText(outputGrep);
					}
					break;
				default:
					mResults.setText("mOutputSpinner.setItemSelectedListener received unexpected position: " + position);
					break;
				}
			}

			@Override
			public void onNothingSelected(AdapterView<?> arg0) {
				NmapError.log("Nothing was selected in mOutputSpinner.");
			}
		});
	}
	
	/**
	 * Print program version and SDK version to log.
	 */
	private void showApkInfo()
	{
		try {
			final int curVersion = getPackageManager().getPackageInfo("com.wjholden.nmap", 0).versionCode;
			NmapError.log("Nmap version: " + curVersion);
			NmapError.log("API Level: " + android.os.Build.VERSION.SDK);
		} catch (NameNotFoundException e) {
			NmapError.log(e.toString());
		}
	}
	
	/**
	 * Added 0.4.7. Forces the activity to restart. Used after user has manually reinstalled binaries.
	 */
	private void forceRestart()
	{
		Intent intent = this.getIntent();
		this.finish();
		startActivity(intent);
	}
	
	/**
	 * Initializes the handler.
	 */
	private void initHandler()
	{
		handler = new Handler() {
			@Override
			public void handleMessage(final Message msg)
			{
				AlertDialog.Builder alert = new AlertDialog.Builder(NmapMain.this).setPositiveButton("OK", new DialogInterface.OnClickListener() {
					
					@Override
					public void onClick(DialogInterface dialog, int which) {
						dialog.dismiss();
					}
				});
				
				if (msg.obj == null)
				{
					NmapError.log("(h-code: " + msg.what + ")");
				}
				else
				{
					NmapError.log((String) msg.obj + " (h-code: " + msg.what + ")");
				}
				
				switch (msg.what)
				{
				case INSTALL_NO_ROOT:
				case RUN_ERROR:
					NmapError.log("Runtime Error");
					showNotification(notificationManager, "Runtime error.", 0, true);
				case INSTALL_ERROR:
					mResults.setText((String) msg.obj);
					alert.setMessage((String) msg.obj);
					alert.show();
					mStart.setText("Start");
					break;
				case INSTALL_GOOD:
					alert.setMessage("This is not an official release by www.nmap.org.\nPlease request support only from wjholden@gmail.com.");
					alert.show();
					break;
				/* Removed in version 28 - see RUN_LINE deprecation warning.
				 * case RUN_LINE:
					mResults.setText(mResults.getText() + "\n" + (String) msg.obj);
					break;*/
				case RUN_SUCCESS_NO_FILE:
					outputGrep = outputXml = outputNmap = (String) msg.obj;
					mResults.setText(outputNmap);
					showNotification(notificationManager, "Scan complete.", 0, true);
					break;
				case RUN_COMPLETE:
					/* TODO: this code is fatally flawed.
					 * Nping/Ncat do not use -oA. They print to stdout like they're supposed to.
					 */
					final String command;
					if (scanType == SCANTYPE_NMAP_SVN || scanType == SCANTYPE_ATRIX)
					{
						command = "nmap";
					}
					else
					{
						command = mCommandSpinner.getSelectedItem().toString();
					}
					outputNmap = NmapUtilities.readOutputFile(command, "nmap");
					outputXml = NmapUtilities.readOutputFile(command, "xml");
					outputGrep = NmapUtilities.readOutputFile(command, "gnmap");
					switch (mOutputSpinner.getSelectedItemPosition()) {
					case 0:
						mResults.setText(outputNmap);
						break;
					case 1:
						mResults.setText(outputXml);
						break;
					case 2:
						mResults.setText(outputGrep);
						break;
					default:
						mResults.setText("Unexpected value in mOutputSpinner.getSelectedItemPosition().");
						break;
					}
					mStart.setText("Start");
					saveUserEntry(); // added 
					NmapError.log("Scan completed in " + msg.arg1 + " seconds.");
					showNotification(notificationManager, "Scan complete.", 0, true);
					break;
				case THREAD_ERROR:
					alert.setMessage("Unable to cancel task.");
					alert.show();
					break;
				case FORCE_RESTART:
					NmapError.log("Forcing Activity restart...");
					deletePreferences = true;
					notificationManager.cancelAll();
					forceRestart();
					break;
				case SET_TITLE:
					NmapMain.this.setTitle(new String(NmapMain.this.getString(R.string.app_name) + (String)msg.obj));
					break;
				case LICENSE_VERIFIED:
					// only enable the scan button when the license verifies.
					mStart.setEnabled(true);
					break;
				case SCAN_STARTED:
					showNotification(notificationManager, "Scan in progress.", 0, false);
					break;
				default:
					NmapError.log("Unexpected case in handler.");
					break;
				}
			}
		};
	}

	@Override
	protected void onStop() {
		if (progressDialog != null)
		{
			progressDialog.dismiss();
		}
		saveUserEntry();
		super.onStop();
	}
	
	/**
	 * This is basically a copy of what's shown as an example on the 
	 * <a href="http://developer.android.com/guide/publishing/licensing.html">Android Licensing Guide</a> by Google.<br />
	 * This inner class provides the basic callbacks handling results from Android licensing.<br />
	 * Just to throw my opinion out there - there's no reason for any developer to use the old DRM anymore. This is too easy.
	 * For an open-source application such as this it's a little silly, but for most people the
	 * <a href="http://en.wikipedia.org/wiki/Public-key_cryptography">PKI</a>-based license verification works beautifully.\
	 * @author William John Holden (wjholden@gmail.com)
	 * @version 0.1
	 * @since 0.5.5
	 */
	private class MyLicenseCheckerCallback implements LicenseCheckerCallback
	{
		/**
		 * Callback for when application passes verification.
		 */
		public void allow() {
			NmapError.log("License verification passed. Enabling normal operation.");
			
			NmapMain.handler.sendEmptyMessage(LICENSE_VERIFIED);
		}

		/**
		 * Callback for errors (prints a generic sort of response.<br />
		 * Google recommends calling dontAllow in this method, but I would rather err
		 * on the side of caution and <i>allow</i> access to the application so I don't
		 * accidentally run afoul of a legitimate user. However, the user will still
		 * see a notification that the error occured (here's hoping they send me the error).
		 */
		public void applicationError(ApplicationErrorCode errorCode) {
			final String error = "An error occured during license verification."; 
			NmapError.log(error);
			NmapError.log(errorCode.toString());
			
			Context context = getApplicationContext();
			int duration = Toast.LENGTH_SHORT;
			Toast toast = Toast.makeText(context, error, duration);
			toast.show();
			
			NmapMain.handler.sendEmptyMessage(LICENSE_VERIFIED);
		}

		@Override
		public void dontAllow() {
			final String error = "License verification failed. Please purchase this program through the Market.";
			NmapError.log(error);
			
			Context context = getApplicationContext();
			int duration = Toast.LENGTH_SHORT;
			Toast toast = Toast.makeText(context, error, duration);
			toast.show();
			
			Intent intent = new Intent(Intent.ACTION_VIEW);
			intent.setData(Uri.parse("market://details?id=com.wjholden.nmap"));
			startActivity(intent);
		}
	}
	
	private void showNotification(NotificationManager nm, String message, int id, boolean complete)
	{
		int icon = R.drawable.icon;
		long when = System.currentTimeMillis();
		Context context = getApplicationContext();
		
		Intent notificationIntent = new Intent(this, NmapMain.class);
		int flags = complete ? Notification.FLAG_AUTO_CANCEL : Notification.FLAG_ONGOING_EVENT;
		PendingIntent contentIntent = PendingIntent.getActivity(this, 0, notificationIntent, flags);
		
		Notification notification = new Notification(icon, message, when);
		notification.setLatestEventInfo(context, "Nmap for Android", message, contentIntent);
		
		nm.notify(id, notification);
	}
	
	private NotificationManager initNotificationManager()
	{
		return (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
	}
}
