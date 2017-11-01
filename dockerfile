FROM ubuntu:14.04 
MAINTAINER Vancir "vancirprince@gmail.com"

ENV DEBIAN_FRONTEND noninteractive 

# set jdk environment
ENV JAVA_HOME /usr/local/jdk1.8.0_151
ENV JRE_HOME $JAVA_HOME/jre
ENV CLASSPATH .:$JAVA_HOME/lib/dt.jar:$JAVA_HOME/lib/tools.jar:$JRE_HOME/lib
ENV PATH $PATH:$JAVA_HOME/bin:$JRE_HOME/bin

# set ubuntu source list
RUN echo "deb http://mirrors.aliyun.com/ubuntu/ trusty main restricted universe multiverse\ndeb http://mirrors.aliyun.com/ubuntu/ trusty-security main restricted universe multiverse\ndeb http://mirrors.aliyun.com/ubuntu/ trusty-updates main restricted universe multiverse\ndeb http://mirrors.aliyun.com/ubuntu/ trusty-proposed main restricted universe multiverse\ndeb http://mirrors.aliyun.com/ubuntu/ trusty-backports main restricted universe multiverse\ndeb-src http://mirrors.aliyun.com/ubuntu/ trusty main restricted universe multiverse\ndeb-src http://mirrors.aliyun.com/ubuntu/ trusty-security main restricted universe multiverse\ndeb-src http://mirrors.aliyun.com/ubuntu/ trusty-updates main restricted universe multiverse\ndeb-src http://mirrors.aliyun.com/ubuntu/ trusty-proposed main restricted universe multiverse\ndeb-src http://mirrors.aliyun.com/ubuntu/ trusty-backports main restricted universe multiverse"  > /etc/apt/sources.list

# update and install some tools
RUN apt-get update -y \
    && apt-get install unzip\
    && apt-get install net-tools

# extract zip and gzip file 
WORKDIR /tmp 
COPY  ./src/apache-tomcat-8.0.46.tar.gz  /tmp/
COPY  ./src/jdk-8u151-linux-x64.tar.gz  /tmp/
COPY  ./src/struts.zip  /tmp/
RUN tar -xz -f jdk-8u151-linux-x64.tar.gz -C /usr/local/
RUN tar -xz -f apache-tomcat-8.0.46.tar.gz -C /usr/local/
RUN unzip struts.zip -d /usr/local/apache-tomcat-8.0.46/webapps

# set REST web program demo
RUN mv /usr/local/apache-tomcat-8.0.46/webapps/struts-2.5.12/apps/struts2-rest-showcase.war /usr/local/apache-tomcat-8.0.46/webapps

EXPOSE 8080 

# start our tomcat 
CMD ["/usr/local/apache-tomcat-8.0.46/bin/catalina.sh", "run"]


