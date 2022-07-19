# Content Loader Extended

## Development

After cloning the repository, please add the following files into `lib/common`. These files can be obtained from the ThingWorx installation directory, in `/apache-tomcat/webapps/Thingworx/WEB-INF/lib`.
The version numbers listed below should serve as just a recommendation, as the actual file versions found in the ThingWorx installation directory might be different.
* `json-20171018.jar`
* `thingworx-common-9.2.3-b189.jar`
* `thingworx-platform-common-9.2.3-b189.jar`
* `joda-time-2.9.jar`
* `slf4j-api-1.7.12.jar`
* 

The folder layout can be modified by editing the project.ext section in the build.gradle file. The default layout is as following:
```gradle
	uiDir = "/ui" // if there are any widgets
	localJarDir = "/lib/local" // if you have any local jars that need to be included in the project, add them here
	srcDir = "${baseDir}/src/main" // where are the sources located
	buildDir = "${baseDir}/build" // where is the build saved
	configDir = "${baseDir}/configfiles" // folder location of the metadata.xml file
	entitiesDir = "${baseDir}/configfiles/Entities" // folder location Entities that are included with the extension
	zipDir = "${baseDir}/zip" // where to store the generated zip 
	thingworxSdkDir = "${baseDir}/lib/twxSdk" // where the thingworx sdk is located
```	
The thingworx related gradle tasks are:
* `packageExtension`: creates in the zipDir an zip archive with the extension
* `upload`: uploads the extension to the specified TWX server.

# This Extension is provided as-is and without warranty or support. It is not part of the PTC product suite. This project is licensed under the terms of the MIT license
