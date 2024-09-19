# Fork info
If you have legacy code that uses older versions of guacamole (0.9.9 in my case) and you are trying to make friends 
with a newer version of guacd (I have 1.5.4) that are not backward compatible, then this will help you build 
guacd 0.9.9 from the sources.

To build a docker image, you just need to call the command from the Dockerfile directory

`
docker build -t guacd:0.9.9 .
`

### More info about my pain and this fork

I had legacy service with old dependencies: 

        <dependency>
            <groupId>org.glyptodon.guacamole</groupId>
            <artifactId>guacamole-common</artifactId>
            <version>0.9.9</version>
            <scope>compile</scope>
        </dependency>
        <dependency>
            <groupId>org.apache.guacamole</groupId>
            <artifactId>guacamole-common-js</artifactId>
            <version>1.0.0</version>
            <type>zip</type>
            <scope>runtime</scope>
        </dependency>

And problem with upper version of guacd 1.5.4:

`
guacd[1]: ERROR:    Guacamole protocol violation. Perhaps the version of guacamole-client is incompatible with this version of guacd?
`

The guacd 0.9.9 image is no longer in the docker hub. It has been relevant for a very long time, since then Apache 
even managed to buy out glyptodon, which wrote guacamole.

I had to build it from source https://github.com/glyptodon/guacd-docker/releases/tag/0.9.9

But it is not so easy to assemble an image from a .tarfile from a github.

I had to fix the Dockerfile, the build script ([download-guacd.sh ](bin%2Fdownload-guacd.sh )) and a couple of files that
broke due to raising the C version, as I understand it.

And after a couple of days of torment, the image is ready.

Next comes the information from the maintainer.

What is guacd?
==============

[guacd](https://github.com/glyptodon/guacamole-server/) is the native
server-side proxy used by the [Guacamole web application](http://guac-dev.org/).
If you wish to deploy Guacamole, or an application using the
[Guacamole core APIs](http://guac-dev.org/api-documentation), you will need a
copy of guacd running.

How to use this image
=====================

Running guacd for use by the [Guacamole Docker image](https://registry.hub.docker.com/u/glyptodon/guacamole/)
-----------------------------------------------------

    docker run --name some-guacd -d glyptodon/guacd

guacd will be listening on port 4822, but this port will only be available to
Docker containers that have been explicitly linked to `some-guacd`.

Running guacd for use services by outside Docker
------------------------------------------------

    docker run --name some-guacd -d -p 4822:4822 glyptodon/guacd

guacd will be listening on port 4822, and Docker will expose this port on the
same server hosting Docker. Other services, such as an instance of Tomcat
running outside of Docker, will be able to connect to guacd.

Beware of the security ramifications of doing this. There is no authentication
within guacd, so allowing access from untrusted applications is dangerous. If
you need to expose guacd, ensure that you only expose it as absolutely
necessary, and that only specific trusted applications have access. 

Connecting to guacd from an application
---------------------------------------

    docker run --name some-app --link some-guacd:guacd -d application-that-uses-guacd

Reporting issues
================

Please report any bugs encountered by opening a new issue in
[our JIRA](http://glyptodon.org/jira/).

