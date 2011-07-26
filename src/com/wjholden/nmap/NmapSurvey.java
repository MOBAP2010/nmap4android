package com.wjholden.nmap;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

/**
 * Allows users to report what SDK version they're running.
 * @author William John Holden
 * @version 0.1
 */
public class NmapSurvey extends Activity implements NmapConstants {

	/**
	 * The button the user clicks on to initiate data upload.
	 */
	private transient Button mButton;
	
	@Override
	protected void onCreate(final Bundle bundle) {
		// TODO Auto-generated method stub
		super.onCreate(bundle);
		setContentView(R.layout.dataupload);
		
		mButton = (Button) findViewById(R.id.btnDataUpload);
		
		mButton.setOnClickListener(new View.OnClickListener() {
			
			public void onClick(final View myView) {
				final UploadData myUploadData = new UploadData();
				
				try
				{
					myUploadData.run();
				}
				catch (Exception e)
				{
					NmapError.log("Error upload data: " + e.toString());
				}
				
				Toast.makeText(getApplicationContext(), "Thank you", Toast.LENGTH_SHORT).show();
				NmapSurvey.this.finish();
			}
		});
	}

	/**
	 * Uploads the ANDROID_ID and Build.VERSION to my webserver so that I can gather just these
	 * analytics on which I will base future development decisions.
	 * @author William John Holden (wjholden@gmail.com)
	 * @version 0.1
	 */
	private class UploadData extends Thread
	{
		/**
		 * <a href="http://developer.android.com/reference/android/os/Build.VERSION.html">Read more about Build.VERSION</a>
		 */
		private final transient String versionSdk;
		
		/**
		 * <a href="http://developer.android.com/reference/android/provider/Settings.Secure.html#ANDROID_ID">Read more about ANDROID_ID</a>
		 */
		private final transient String androidId;
		
		/**
		 * Name of the app that is being reported.
		 */
		private final transient String appName;

		/**
		 * The location where the data gets uploaded to.
		 */
		private final static String UPLOAD_URI = "http://nmap.wjholden.com/data.php";
		
		/**
		 * Constructor...although this does not strictly have to contain this logic inside it, I wanted it there for easier debugging.
		 */
		public UploadData()
		{
			super();
			
			versionSdk = android.os.Build.VERSION.SDK;
			androidId = android.provider.Settings.Secure.getString(getContentResolver(), android.provider.Settings.Secure.ANDROID_ID);
			appName = NmapSurvey.this.getString(R.string.app_name);
			NmapError.log("Version SDK = " + versionSdk);
			NmapError.log("Android ID = " + androidId);
		}
		
		/**
		 * Very basic Apache HTTP POST routine.
		 */
		public void run()
		{
			try
			{
				final DefaultHttpClient client = new DefaultHttpClient();
				final URL url = new URL(UPLOAD_URI);
				final URI uri = new URI(url.getProtocol(), url.getHost(), url.getPath(), url.getQuery(), null);
				final HttpPost httppost = new HttpPost(uri);
				
				final List<NameValuePair> nvps = new ArrayList<NameValuePair>();
				nvps.add(new BasicNameValuePair("versionSdk", versionSdk));
				nvps.add(new BasicNameValuePair("androidId", androidId));
				nvps.add(new BasicNameValuePair("appName", appName));
				httppost.setEntity(new UrlEncodedFormEntity(nvps));
				
				final HttpResponse response = client.execute(httppost);
				final int status = response.getStatusLine().getStatusCode();
				
				NmapError.log("Server responded with status=" + status);
			} catch (URISyntaxException e) {
				NmapError.log(e.toString());
			} catch (MalformedURLException e) {
				NmapError.log(e.toString());
			} catch (UnsupportedEncodingException e) {
				NmapError.log(e.toString());
			} catch (ClientProtocolException e) {
				NmapError.log(e.toString());
			} catch (IOException e) {
				NmapError.log(e.toString());
			}
		}
	}
}
