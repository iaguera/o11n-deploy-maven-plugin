/* This file is part of project "o11n-deploy-maven-plugin", a computer software     *
 * plugin for deploying Java plugins to VMware vRealize Orchestrator using          *
 * Maven build management.                                                          *
 *                                                                                  *
 *                                                                                  *
 * Copyright (C) 2016-2017 Robert Szymczak (m451@outlook.com)                       *
 *                                                                                  *
 * This program is free software: you can redistribute it and/or modify             *
 * it under the terms of the GNU Lesser General Public License as published         *
 * by the Free Software Foundation, either version 3 of the License, or             *
 * (at your option) any later version.                                              *
 *                                                                                  *
 * This program is distributed in the hope that it will be useful,                  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of                   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                             *
 * See the GNU Lesser General Public License for more details.                      *
 *                                                                                  *
 * You should have received a copy of the GNU Lesser General Public License         *
 * along with this program. If not, see <http://www.gnu.org/licenses/>.             */
package com.github.m451.o11n_deploy_maven_plugin;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.json.JsonObject;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.ProcessingException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.ResponseProcessingException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import org.apache.maven.model.Build;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;
import org.glassfish.jersey.jsonp.JsonProcessingFeature;
import org.glassfish.jersey.media.multipart.FormDataMultiPart;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.glassfish.jersey.media.multipart.file.FileDataBodyPart;

/**
 * Mojo which deploys a created VMware Orchestrator plug-in to the configured VMware Orchestrator Server.
 * This Mojo should be configured within your o11nplugin-PLUGINNAME/pom.xml Maven module.
 * @see <a href="https://github.com/m451/o11n-deploy-maven-plugin">Project page on GitHub</a>.
 * 
 * @author Robert Szymczak
 */
@Mojo(name = "deployplugin", defaultPhase = LifecyclePhase.INSTALL)
public class DeployPlugin extends AbstractMojo
{
    // Taken from Maven API through PluginParameterExpressionEvaluator
    @Parameter(defaultValue = "${project}", readonly = true)
    private MavenProject project;

    // Server Configuration
    @Parameter(defaultValue = "localhost", property = "deployplugin.server", required = true)
    /**
     * VMware Orchestrator Server Hostname or IP-address.
     */
    private String o11nServer;
    @Parameter(defaultValue = "8281", property = "deployplugin.pluginserviceport", required = false)
    /**
     * VMware Orchestrator Plugin Service REST API Port, usually 8281.
     */
    private Integer o11nServicePort;
    @Parameter(defaultValue = "8283", property = "deployplugin.configserviceport", required = false)
    /**
     * VMware Orchestrator Config Service REST API Port, usually 8283.
     */
    private Integer o11nConfigPort;
    @Parameter(defaultValue = "vcoadmin", property = "deployplugin.pluginserviceuser", required = true)
    /**
     * Username of a user with sufficient permissions to import vRO plug-ins.
     * <b>Note:</b> when using vRO integrated LDAP this will be 'vcoadmin' and 'root' has no permissions to use the plug-in service API by default.
     * 
     */
    private String o11nPluginServiceUser;
    @Parameter(defaultValue = "vcoadmin", property = "deployplugin.pluginservicepassword", required = true)
    /**
     * Password of the provided <code>o11nPluginServiceUser</code>.
     */
    private String o11nPluginServicePassword;

    @Parameter(defaultValue = "root", property = "deployplugin.configserviceuser", required = false)
    /**
     * Username of a user with sufficient permissions to restart vRO services.
     * <b>Note</b>: when using vRO integrated LDAP this will be 'root' and 'vcoadmin' has no permissions to use the config service API by default.
     */
    private String o11nConfigServiceUser;
    @Parameter(property = "deployplugin.configservicepassword", required = false)
    /**
     * Password of the provided <code>o11nConfigServiceUser</code>.
     */
    private String o11nConfigServicePassword;

    // Plug-in Configuration
    @Parameter(defaultValue = "${project.build.directory}", property = "deployplugin.pluginpath", required = false)
    /**
     * Path to the plug-in file that should be installed.
     * The filename will be taken from the configured <code>o11nPluginFileName</code>.
     */
    private String o11nPluginFilePath;
    @Parameter(defaultValue = "${project.build.finalName}", property = "deployplugin.pluginfile", required = false)
    /**
     * The plug-in filename of the plug-in that should be installed omitting any file extension. 
     * The extension will be taken from the configured <code>o11nPluginType</code>.
     */
    private String o11nPluginFileName;
    @Parameter(defaultValue = "vmoapp", property = "deployplugin.plugintype", required = false)
    /**
     * The vRO plug-in format. Might be <tt>dar</tt> or <tt>vmoapp</tt>.
     */
    private String o11nPluginType;
    @Parameter(defaultValue = "true", property = "deployplugin.overwrite", required = false)
    /**
     * Forces vRO to reinstall the plug-in.
     */
    private boolean o11nOverwrite;
    @Parameter(defaultValue = "false", property = "deployplugin.restart", required = false)
    /**
     * Triggers a vRO service restart after the plug-in was installed if set to <code>true</code>.
     */
    private boolean o11nRestartService;

    // Static globals
    private static File file = null;
    private static enum ServiceStatus
    {
        RUNNING, STOPPED, RESTARTING, UNDEFINED;
    }

    public void execute() throws MojoExecutionException, MojoFailureException
    {
        // Force set all non-required parameters in case user accidently set them null
        Build build = project.getBuild();
        if (o11nPluginFilePath == null || o11nPluginFilePath.isEmpty())
        {
            o11nPluginFilePath = build.getDirectory();
        }

        if (o11nPluginFileName == null || o11nPluginFilePath.isEmpty())
        {
            o11nPluginFileName = build.getFinalName();
        }
        if (o11nPluginType == null || o11nPluginType.isEmpty())
        {
            // may be dar or vmoapp
            o11nPluginType = "dar";
        }
        if (o11nServicePort == null || o11nServicePort < 1 || o11nServicePort > 65535)
        {
            o11nServicePort = 8281;
        }
        if (o11nConfigPort == null || o11nConfigPort < 1 || o11nConfigPort > 65535)
        {
            o11nConfigPort = 8283;
        }
        if(o11nRestartService)
        {
            if(o11nConfigServiceUser == null || o11nConfigServiceUser.isEmpty())
            {
                throw new MojoFailureException("Error: 'o11nRestartService' was set to 'true' but no 'o11nConfigServiceUser' was provided.");
            }
            if(o11nPluginServicePassword == null || o11nPluginServicePassword.isEmpty())
            {
                throw new MojoFailureException("Error: 'o11nRestartService' was set to 'true' but no 'o11nPluginServicePassword' was provided.");
            }
        }

        // Example: D:\Workspace\coopto\o11nplugin-coopto\target\o11nplugin-PLUGINNAME-0.1.vmoapp
        file = new File(o11nPluginFilePath + "\\" + o11nPluginFileName + "." + o11nPluginType);

        if (file.exists())
        {
            // 1. Upload plug-in
            Boolean uploadSuccessed = uploadPlugin();
            if (uploadSuccessed)
            {
                getLog().info("Finished Plug-in upload.");

                if (o11nRestartService)
                {
                    // 2. Restart service
                    getLog().info("Service restart was requested.");
                    Boolean restartTriggered = restartService();

                    if (restartTriggered)
                    {
                        try
                        {
                            Thread.sleep(1000);
                        } catch (InterruptedException e)
                        {
                            StringWriter sw = new StringWriter();
                            PrintWriter pw = new PrintWriter(sw, true);
                            e.printStackTrace(pw);
                            throw new MojoExecutionException("Error while executing 'O11N-DEPLOY-MAVEN-PLUGIN':\n" + sw.getBuffer().toString());
                        }

                        // 3. Wait for service restart
                        int timeout = 12;
                        int counter = 0;
                        while (getServiceStatus() == ServiceStatus.RESTARTING)
                        {
                            if (counter >= timeout)
                            {
                                getLog().warn("Timeout. vRO service is not responding. Please verify your vRO configuration.");
                                break;
                            }
                            counter++;

                            try
                            {
                                Thread.sleep(5000);
                            } catch (InterruptedException e)
                            {
                                StringWriter sw = new StringWriter();
                                PrintWriter pw = new PrintWriter(sw, true);
                                e.printStackTrace(pw);
                                throw new MojoExecutionException("Error while executing 'O11N-DEPLOY-MAVEN-PLUGIN':\n" + sw.getBuffer().toString());
                            }
                        }

                        // Return service status info
                        ServiceStatus status = getServiceStatus();
                        switch (status)
                        {
                        case RUNNING:
                            getLog().info("Finished vRO service restart.");
                            getLog().info("Successfully updated plug-in in VMware Orchestrator.");
                            break;
                        case STOPPED:
                            getLog().warn("vRO service could not be started. Please verify your vRO configuration.");
                            break;
                        default:
                            getLog().warn("vRO service returned a unknown status. Please verify your vRO configuration.");
                            break;
                        }
                    } else
                    {
                        throw new MojoFailureException("vRO service restart has failed. Please restart vRO service manually for the changes to take effect.");
                    }
                } else
                {
                    getLog().info("vRO service restart was not requested. Please restart vRO service manually for the changes to take effect.");
                }
            } else
            {
                throw new MojoFailureException("Plug-in upload has failed.");
            }
        } else
        {
            throw new MojoFailureException("Plug-in file not found.");
        }
    }

    // Uploads the plug-in submitted to this Mojo. Returns true if the upload was successfull and false otherwise.
    private boolean uploadPlugin() throws MojoFailureException, MojoExecutionException
    {
        // Example: https://localhost:8281
        URI pluginServiceBaseUri = UriBuilder.fromUri("https://" + o11nServer + ":" + o11nServicePort.toString()).build();
        HttpAuthenticationFeature pluginServiceAuth = HttpAuthenticationFeature.basic(o11nPluginServiceUser, o11nPluginServicePassword);

        return uploadPlugin(pluginServiceBaseUri, pluginServiceAuth, o11nPluginType, String.valueOf(o11nOverwrite), file);
    }

    private boolean uploadPlugin(URI apiEndpoint, HttpAuthenticationFeature auth, String type, String overwrite, File file) throws MojoFailureException, MojoExecutionException
    {
        getLog().info("Starting Plug-in upload...");
        getLog().info("Configured plug-in path: '" + file.getAbsolutePath() + "'.");
        getLog().info("Configured plug-in service URL: '" + apiEndpoint.toString() + "'.");

        Client pluginServiceClient = null;
        FileDataBodyPart fileDataBodyPart = null;
        FormDataMultiPart formDataMultiPart = null;
        Response response = null;

        try
        {
            pluginServiceClient = getUnsecureClient();
            pluginServiceClient.register(auth);

            try
            {
                fileDataBodyPart = new FileDataBodyPart("file", file, MediaType.APPLICATION_OCTET_STREAM_TYPE);
                formDataMultiPart = new FormDataMultiPart();
                formDataMultiPart.bodyPart(fileDataBodyPart);
                formDataMultiPart.field("format", type);
                formDataMultiPart.field("overwrite", overwrite);

                response = pluginServiceClient.target(apiEndpoint).path("/vco/api/plugins").request(MediaType.WILDCARD_TYPE).post(Entity.entity(formDataMultiPart, MediaType.MULTIPART_FORM_DATA_TYPE));

                getLog().debug("Returned Response code: '" + response.getStatus() + "'.");
                getLog().debug("Returned Response: '" + response.toString() + "'.");

                int statusCode = response.getStatus();
                switch (statusCode)
                {
                case 201:
                    getLog().debug("HTTP 201. Successfully updated plug-in in VMware Orchestrator.");
                    return true;
                case 204:
                    getLog().debug("HTTP 204. Successfully updated plug-in in VMware Orchestrator.");
                    return true;
                case 401:
                    getLog().warn("HTTP 401. Authentication is required to upload a plug-in.");
                    return false;
                case 403:
                    getLog().warn("HTTP 403. The provided user is not authorized to upload a plug-in.");
                    return false;
                case 404:
                    getLog().warn("HTTP 404. The requested ressource was not found. Make sure you entered the correct VMware Orchestrator URL and that VMware Orchestrator is reachable under that URL from the machine running this Maven Mojo.");
                    return false;
                case 409:
                    getLog().warn("HTTP 409. The provided plug-in already exists and the overwrite flag was not set. The plug-in will not be changed in VMware Orchestrator.");
                    return false;
                default:
                    getLog().warn("Unkown status code HTTP '" + statusCode + "' returned from VMware Orchestrator. Please verify if the plug-in has been updated sucessfully. I really got no clue.");
                    return false;
                }
            } catch (ResponseProcessingException ex)
            {
                // Thrown in case processing of a received HTTP response fails
                StringWriter sw = new StringWriter();
                PrintWriter pw = new PrintWriter(sw, true);
                ex.printStackTrace(pw);
                throw new MojoFailureException("A ResponseProcessingException occured while uploading plug-in data:\n" + sw.getBuffer().toString());
            } catch (ProcessingException ex)
            {
                // Thrown in case the request processing or subsequent I/O operation fail.
                // THIS IS THROWN in case the server is currently not available e.g. because the service is currently
                // beeing restarted
                StringWriter sw = new StringWriter();
                PrintWriter pw = new PrintWriter(sw, true);
                ex.printStackTrace(pw);
                throw new MojoFailureException("A ProcessingException occured while uploading plug-in data:\n" + sw.getBuffer().toString());
            } finally
            {
                // release resources
                if (fileDataBodyPart != null)
                {
                    fileDataBodyPart.cleanup();
                }
                if (formDataMultiPart != null)
                {
                    try
                    {
                        formDataMultiPart.cleanup();
                        formDataMultiPart.close();
                    } catch (IOException ex)
                    {
                        StringWriter sw = new StringWriter();
                        PrintWriter pw = new PrintWriter(sw, true);
                        ex.printStackTrace(pw);
                        getLog().warn("Warning: unable to close FormDataMultiPart stream. Terminate your JVM to prevent memory leaks. Exception:\n" + sw.getBuffer().toString());
                    }
                }
                if (response != null)
                {
                    response.close();
                }
            }
        } catch (Exception e)
        {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw, true);
            e.printStackTrace(pw);
            throw new MojoExecutionException("Unable to create HTTP client. Exception:\n" + sw.getBuffer().toString());
        } finally
        {
            // release resources
            if (pluginServiceClient != null)
            {
                pluginServiceClient.close();
            }
        }
    }

    // Triggers a vRO service restart. Returns true if execution was successfull and false otherwise.
    private Boolean restartService() throws MojoFailureException, MojoExecutionException
    {
        // Example: https://localhost:8283
        URI configServiceBaseUri = UriBuilder.fromUri("https://" + o11nServer + ":" + o11nConfigPort.toString()).build();
        HttpAuthenticationFeature configServiceAuth = HttpAuthenticationFeature.basic(o11nConfigServiceUser, o11nConfigServicePassword);

        return restartService(configServiceBaseUri, configServiceAuth);
    }

    private Boolean restartService(URI apiEndpoint, HttpAuthenticationFeature auth) throws MojoFailureException, MojoExecutionException
    {
        getLog().info("Restarting vRO service...");
        getLog().info("Configured config service URL: '" + apiEndpoint.toString() + "'.");

        Client configServiceClient = null;
        Response response = null;

        try
        {
            configServiceClient = getUnsecureClient();
            configServiceClient.register(auth);

            try
            {
                response = configServiceClient.target(apiEndpoint).path("/vco-controlcenter/api/server/status/restart").request(MediaType.APPLICATION_JSON_TYPE).post(Entity.json(null));
                JsonObject statusResponse = response.readEntity(JsonObject.class);

                int statusCode = response.getStatus();
                switch (statusCode)
                {
                case 200:
                case 201:
                case 204:
                    // Don't use JsonObject.getString since the returned currentStatus might be null
                    // Rather use JsonObject.get which will return the value or JsonValue.NULL if it's null
                    // In addition JsonObject.isNull(String key) can be used for testing the retun value
                    getLog().debug("vRO service status: " + statusResponse.get("currentStatus"));
                    getLog().debug("Triggered vRO service restart.");
                    return true;
                case 401:
                    getLog().warn("HTTP 401. Authentication is required to restart the vRO service.");
                    return false;
                case 403:
                    getLog().warn("HTTP 403. The provided user is not authorized to restart the vRO service.");
                    return false;
                case 404:
                    getLog().warn("HTTP 404. The requested ressource was not found. Make sure you entered the correct VMware Orchestrator URL and that VMware Orchestrator is reachable under that URL from the machine running this Maven Mojo.");
                    return false;
                default:
                    getLog().warn("Unkown status code HTTP " + statusCode + " returned from VMware Orchestrator. Please verify if the service has been restarted. I really got no clue.");
                    return false;
                }
            } catch (ResponseProcessingException ex)
            {
                // Thrown in case processing of a received HTTP response fails
                StringWriter sw = new StringWriter();
                PrintWriter pw = new PrintWriter(sw, true);
                ex.printStackTrace(pw);
                throw new MojoFailureException("A ResponseProcessingException occured while restarting vRO service:\n" + sw.getBuffer().toString());
            } catch (ProcessingException ex)
            {
                // Thrown in case the request processing or subsequent I/O operation fail.
                StringWriter sw = new StringWriter();
                PrintWriter pw = new PrintWriter(sw, true);
                ex.printStackTrace(pw);
                throw new MojoFailureException("A ProcessingException occured while restarting vRO service:\n" + sw.getBuffer().toString());
            } finally
            {
                // release resources
                if (response != null)
                {
                    response.close();
                }
            }
        } catch (Exception e)
        {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw, true);
            e.printStackTrace(pw);
            throw new MojoExecutionException("Unable to create HTTP client. Exception:\n" + sw.getBuffer().toString());
        } finally
        {
            // release resources
            if (configServiceClient != null)
            {
                configServiceClient.close();
            }
        }
    }

    // Returns the current vRO service status.
    private ServiceStatus getServiceStatus() throws MojoFailureException, MojoExecutionException
    {
        // Example: https://localhost:8283
        URI configServiceBaseUri = UriBuilder.fromUri("https://" + o11nServer + ":" + o11nConfigPort.toString()).build();
        HttpAuthenticationFeature configServiceAuth = HttpAuthenticationFeature.basic(o11nConfigServiceUser, o11nConfigServicePassword);

        return getServiceStatus(configServiceBaseUri, configServiceAuth);
    }

    private ServiceStatus getServiceStatus(URI apiEndpoint, HttpAuthenticationFeature auth) throws MojoFailureException, MojoExecutionException
    {
        getLog().debug("Getting vRO service status...");
        getLog().debug("Configured config service URL: '" + apiEndpoint.toString() + "'.");

        Client configServiceClient = null;
        Response response = null;

        try
        {
            configServiceClient = getUnsecureClient();
            configServiceClient.register(auth);

            try
            {
                response = configServiceClient.target(apiEndpoint).path("/vco-controlcenter/api/server/status").request(MediaType.APPLICATION_JSON_TYPE).get();
                JsonObject statusResponse = response.readEntity(JsonObject.class);

                int statusCode = response.getStatus();
                switch (statusCode)
                {
                case 200:
                case 201:
                case 204:
                    // Don't use JsonObject.getString since the returned currentStatus might be null
                    // Rather use JsonObject.get which will return the value or JsonValue.NULL if it's null
                    // In addition JsonObject.isNull(String key) can be used for testing the retun value
                    getLog().debug("vRO service status: " + statusResponse.get("currentStatus"));

                    // Status should be "RUNNING", "STOPPED", "UNDEFINED" or NULL
                    if (statusResponse.isNull("currentStatus"))
                    {
                        return ServiceStatus.RESTARTING;
                    } else if (statusResponse.getString("currentStatus").equalsIgnoreCase("RUNNING"))
                    {
                        return ServiceStatus.RUNNING;
                    } else if (statusResponse.getString("currentStatus").equalsIgnoreCase("STOPPED"))
                    {
                        return ServiceStatus.STOPPED;
                    } else
                    {
                        return ServiceStatus.UNDEFINED;
                    }
                case 401:
                    getLog().warn("HTTP 401. Authentication is required to get service status.");
                    return ServiceStatus.UNDEFINED;
                case 403:
                    getLog().warn("HTTP 403. The provided user is not authorized to get the service status.");
                    return ServiceStatus.UNDEFINED;
                case 404:
                    getLog().warn("HTTP 404. The requested ressource was not found. Make sure you entered the correct VMware Orchestrator URL and that VMware Orchestrator is reachable under that URL from the machine running this Maven Mojo.");
                    return ServiceStatus.UNDEFINED;
                default:
                    getLog().warn("Unkown status code HTTP " + statusCode + " returned from VMware Orchestrator. Please verify if the service has been restarted. I really got no clue.");
                    return ServiceStatus.UNDEFINED;
                }
            } catch (ResponseProcessingException ex)
            {
                // Thrown in case processing of a received HTTP response fails
                StringWriter sw = new StringWriter();
                PrintWriter pw = new PrintWriter(sw, true);
                ex.printStackTrace(pw);
                throw new MojoFailureException("A ResponseProcessingException occured while requesting vRO service status:\n" + sw.getBuffer().toString());
            } catch (ProcessingException ex)
            {
                // Thrown in case the request processing or subsequent I/O operation fail.
                StringWriter sw = new StringWriter();
                PrintWriter pw = new PrintWriter(sw, true);
                ex.printStackTrace(pw);
                throw new MojoFailureException("A ProcessingException occured while requesting vRO service status:\n" + sw.getBuffer().toString());
            } finally
            {
                // release resources
                if (response != null)
                {
                    response.close();
                }
            }
        } catch (Exception e)
        {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw, true);
            e.printStackTrace(pw);
            throw new MojoExecutionException("Unable to create HTTP client. Exception:\n" + sw.getBuffer().toString());
        } finally
        {
            // release resources
            if (configServiceClient != null)
            {
                configServiceClient.close();
            }
        }
    }

    // Returns a Jersey HTTP client properly configured to be used with this Mojo
    private Client getUnsecureClient() throws KeyManagementException, NoSuchAlgorithmException
    {
        // BEGIN -- Allow Self-Signed vRO-Certificates
        // TODO Build in option to provide the trusted certificate
        SSLContext disabledSslContext = SSLContext.getInstance("TLS");
        disabledSslContext.init(null, new TrustManager[]
        { new X509TrustManager()
        {
            public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException
            {
            }

            public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException
            {
            }

            public X509Certificate[] getAcceptedIssuers()
            {
                return new X509Certificate[0];
            }

        } }, new java.security.SecureRandom());
        // END -- Allow Self-Signed vRO-Certificates

        // BEGIN -- Allow Hostname CN missmatch
        HostnameVerifier disabledHostnameVerification = new HostnameVerifier()
        {
            @Override
            public boolean verify(String hostname, SSLSession session)
            {
                return true;
            }
        };
        // END -- Allow Hostname CN missmatch

        // Fiddler Debugging Proxy Option
        /**
         * System.setProperty ("http.proxyHost", "127.0.0.1");
         * System.setProperty ("http.proxyPort", "8888");
         * System.setProperty ("https.proxyHost", "127.0.0.1");
         * System.setProperty ("https.proxyPort", "8888");
         **/

        ClientConfig config = new ClientConfig();
        config.register(MultiPartFeature.class); // Enable Jersey MultiPart feature
        config.register(JsonProcessingFeature.class); // Enable JSON-P JSON processing
        // config.property(LoggingFeature.LOGGING_FEATURE_VERBOSITY_CLIENT, LoggingFeature.Verbosity.PAYLOAD_ANY);  // Optional enable client logging for Debugging
        // config.property(LoggingFeature.LOGGING_FEATURE_LOGGER_LEVEL_CLIENT, "INFO");                             // Optional enable client logging for Debugging

        return ClientBuilder.newBuilder().withConfig(config).sslContext(disabledSslContext).hostnameVerifier(disabledHostnameVerification).build();
    }
}
