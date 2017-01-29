# O11n-deploy-maven-plugin

A Maven plug-in that helps you develop Java plug-ins for VMware vRealize Orchestrator by automatically installing the compiled *.vmoapp or *.dar files on the configured vRealize Orchestrator server.

#### New in version 0.2.0
- Added Orchestrator service restart option
- Added better permission control
- Maven debug mode will now provide verbose output
- Replaced *Unirest* with *Jersey 2.0* and *JSON-P*

#### New in version 0.2.1
- Added option to delete plug-in packages (thanks @gvart)
- Minor formatting and spelling fixes

#### New in version 0.2.2
- Minor Javadoc fixes
- Added option to wait for pending configuration changes

## Install
You may download this Mojo as a binary and add it to your local Maven repository for usage. In addition this Mojo is available in the public OSSRH repository hosted by Sonatype and will automatically be pulled from there when added to your project's Maven POM.
If you have not yet added the Sonatype OSSRH you can do so by adding the following to your POM.

```xml
<repositories>
    <repository>
        <id>sonatype-oss-public</id>
        <url>https://oss.sonatype.org/content/groups/public/</url>
        <releases>
            <enabled>true</enabled>
        </releases>
    </repository>
</repositories>
```

## Usage
This Mojo should be configured within your *o11nplugin-**pluginname**/pom.xml* Maven module. It has a single goal **deployplugin** and usually you should run it in the **install** phase. The **deployplugin** goal has the following parameters.


#### Mandatory Parameters
- **o11nServer**: VMware Orchestrator server hostname or IP-address.
- **o11nPluginServiceUser**: Username of a user with sufficient permissions to import Orchestrator plug-ins. *Note: when using integrated LDAP this will be `vcoadmin` and `root` has no permissions to use the plug-in service API by default.*
- **o11nPluginServicePassword**: Password of the provided `o11nPluginServiceUser`.

#### Optional Parameters
- **o11nServicePort**: VMware Orchestrator Plugin Service REST API Port. Defaults to `8281`.
- **o11nConfigPort**: VMware Orchestrator Config Service REST API Port. Defaults to `8283`.
- **o11nOverwrite**: If set to `true` this option will trigger a Orchestrator service restart after the plug-in was installed. Defaults to `true`.
- **o11nPluginType**: The Orchestrator plug-in bundle format. Might be `DAR` or `VMOAPP`. Defaults to `VMOAPP`. *Note*: the value for this parameter is case-sensitive!
- **o11nRestartService**: If set to `true` this option will trigger a Orchestrator service restart after the plug-in was installed.
- **o11nConfigServiceUser**: Username of a user with sufficient permissions to restart Orchestrator services. **Required if `o11nRestartService` was set to `true`**. *Note: when using integrated LDAP this will be `root` and `vcoadmin` has no permissions to use the config service API by default.*
- **o11nConfigServicePassword**: Password of the provided `o11nConfigServiceUser`. **Required if `o11nRestartService` was set to `true`**.
- **o11nDeletePackage**: If set to `true` this option will delete all of the plug-ins packages before installing the new plug-in. *Note*: any changes done to the plug-in workflows and not synced with the packages in the plug-in bundle will be lost! The Orchestrator API option `deletePackageKeepingShared` is used internally for safety.
- **o11nPackageName**: The package name of the plug-in package to be deleted. **Required if `o11nDeletePackage` was set to `true`**. *Note*: this is the package name as specified in the `pkg-name` attribute of the `dunes-meta-inf.xml` file. If the package is not found on the server the goal execution will continue but a warning will be logged.
- **o11nWaitForPendingChanges**: If set to `true` this option will make this Mojo wait up to 240 seconds till the pending configuration changes have been applied. Note*: this option will only be processed if `o11nRestartService` is set to `true`.
- **o11nPluginFilePath**: Path to the plug-in file that should be installed. Defaults to `${project.build.directory}`. The filename will be taken from the configured *o11nPluginFileName*.
- **o11nPluginFileName**: The plug-in filename of the plug-in that should be installed omitting any file extension. Defaults to `${project.build.finalName}`. The extension will be taken from the configured *o11nPluginType*.

#### Parameter Formatting
All parameters are provided as Strings inside your POM file and will be converted into the required format internally. A simple `mvn install` will then trigger the upload of the compiled plugin if the execution goal has been set, see [example configuration](#example-configuration).

### Example configuration
A example that uses all currently available parameters. Note that for illustration purpose we also configured the optional parameters which would use the documented default values if omitted.

```xml
<plugin>
    <groupId>com.github.m451</groupId>
    <artifactId>o11n-deploy-maven-plugin</artifactId>
    <version>0.2.2</version>
    <executions>
        <execution>
            <phase>install</phase>
            <goals>
                <goal>deployplugin</goal>
            </goals>
        </execution>
    </executions>
    <configuration>
      <o11nServer>localhost</o11nServer>
      <o11nServicePort>8281</o11nServicePort>
      <o11nConfigPort>8283</o11nConfigPort>
      <o11nPluginServiceUser>vcoadmin</o11nPluginServiceUser>
      <o11nPluginServicePassword>vcoadmin</o11nPluginServicePassword>
      <o11nConfigServiceUser>root</o11nConfigServiceUser>
      <o11nConfigServicePassword>RootP$$word</o11nConfigServicePassword>
      <o11nPluginType>VMOAPP</o11nPluginType>
      <o11nOverwrite>true</o11nOverwrite>
      <o11nRestartService>true</o11nRestartService>
      <o11nWaitForPendingChanges>true</o11nWaitForPendingChanges>
      <o11nDeletePackage>true</o11nDeletePackage>
      <o11nPackageName>com.example.packagename</o11nPackageName>
      <o11nPluginFilePath>${project.build.directory}<o11nPluginFilePath>
      <o11nPluginFileName>${project.build.finalName}</o11nPluginFileName>
    </configuration>
</plugin>
<!-- Optional, see 'install' section of this readme -->
<repositories>
    <repository>
        <id>sonatype-oss-public</id>
        <url>https://oss.sonatype.org/content/groups/public/</url>
        <releases>
            <enabled>true</enabled>
        </releases>
    </repository>
</repositories>
```


### Example execution
An example output of a successfull run may look like this:
```bash
...
[INFO] --- o11n-deploy-maven-plugin:0.2.1:deployplugin (default) @ o11nplugin-pluginname ---
[INFO] Package deletion was requested.
[INFO] Deleting plug-in package 'com.example.packagename.'...
[INFO] Finished plug-in package deletion.
[INFO] Starting Plug-in '/workspace/pluginname/o11nplugin-pluginname/target/o11nplugin-pluginname-0.1.vmoapp' upload...
[INFO] Finished plug-in upload.
[INFO] Service restart was requested.
[INFO] Restarting Orchestrator service...
[INFO] Wait for pending changes was requested.
[INFO] Configuration changes are still pending. Waiting...
[INFO] Configuration changes are still pending. Waiting...
[INFO] Configuration changes are still pending. Waiting...
[INFO] Configuration changes are still pending. Waiting...
[INFO] Pending configuration changes have been applied. All done.
[INFO] Finished Orchestrator service restart.
[INFO] Successfully updated plug-in in VMware Orchestrator.
...
```

## Licensing & Legal
O11n-deploy-maven-plugin – from now on “this project”, “this program” or “this software” – is an open source project.

*This program is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.*

*This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.*

*You should have received a copy of the GNU Lesser General Public License along with this program. If not, see http://www.gnu.org/licenses/.*


This software may include *“Open Source Software”*, which means various open source software components licensed under the terms of applicable open source license agreements included in the materials relating to such software. Open Source Software is composed of individual software components, each of which has its own copyright and its own applicable license conditions. Information about the used Open Source Software and their licenses can be found in the *pom.xml* file. The Product may also include other components, which may contain additional open source software packages. One or more such *license* files may therefore accompany this Product.

It is your responsibility to ensure that your use and/or transfer does not violate applicable laws. 

All product and company names are trademarks ™ or registered ® trademarks of their respective holders. Use of them does not imply any affiliation with or endorsement by them.