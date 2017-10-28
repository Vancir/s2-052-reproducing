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

通过建立docker容器来搭建实验环境，保证复现过程的安全性和便* 林颖萱：负责收集过往Struts2的漏洞分析文章，利用代码及防御策略等
携性。在docker环境中安装Apache Tomcat，Struts 2以及Java等基础环境。

编写python脚本构造payload，对漏洞利用过程进行复现。当然也可以直接使用burpsuite直接发送恶意xml数据来实现利用过程。Metasploit也已经更新有该漏洞的攻击模块。

至于最终的利用效果，对于远程代码执行漏洞(RCE)，我们尝试通过利用漏洞从服务器端反弹一个shell来实现对服务器的控制。

在整个复现过程中使用Wireshark来跟踪TCP流，分析网络数据包进行分析。

## 0x03 漏洞分析

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

## 0x04 漏洞修复情况

新版本中增加了`XStreamPermissionProvider`，并且对原先有问题的`createXStream`进行重写，增加了校验，拒绝不安全的类执行

## 0x05 Struts 2过往漏洞情况

Apache Struts 2漏洞频发，过往有大量的该产品的漏洞预警。安全分析人士甚至编写有Struts2全漏洞检测脚本。通过对往期Struts2漏洞，分析Struts2常见的攻击方式并总结Struts2的一些修复建议。

## 0x06 S2-052 修复建议

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
 