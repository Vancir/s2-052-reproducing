# Apache Struts2 S2-052(CVE-2017-9805)远程代码执行漏洞

## 0x00 漏洞描述

2017年9月5日，Apache Struts发布最新安全公告，Apache Struts2的REST插件存在远程代码执行的高危漏洞，该漏洞由lgtm.com的安全研究员汇报，漏洞编号为CVE-2017-9805（S2-052）。

## 0x01 漏洞影响

启用Struts REST插件并使用XStream组件对XML进行反序列操作时，未对数据内容进行有效验证，可被攻击者进行远程代码执行攻击(RCE)。

实际场景中存在一定局限性，需要满足一定条件，非struts本身默认开启的组件。


## 影响版本

* Version 2.5.0 to 2.5.12
* Version 2.1.2 to 2.3.33

## 修复建议

* 升级至Struts 2.5.13或Struts 2.3.34版本
* 在不使用时移除移除Struts REST插件
* 限制REST插件仅处理服务器正常页面和JSON文件
    1. Disable handling XML pages and requests to such pages
    ```java
    <constant name="struts.action.extension" value="xhtml,,json" />
    ```
    2. Override getContentType in XStreamHandler
    ``` java
    public class MyXStreamHandler extends XStreamHandler { public String getContentType() {
        return "not-existing-content-type-@;/&%$#@";
        }
    }
    ```    
    3. Register the handler by overriding the one provided by the framework in your struts.xml
    ```java
    <bean type="org.apache.struts2.rest.handler.ContentTypeHandler" name="myXStreamHandmer" class="com.company.MyXStreamHandler"/>
    <constant name="struts.rest.handlerOverride.xml" value="myXStreamHandler"/>
    ```
## 0x02 环境搭建



## 0xFF 参考资料
[Using QL to find a remote code execution vulnerability in Apache Struts (CVE-2017-9805)](https://lgtm.com/blog/apache_struts_CVE-2017-9805)

[Apache Struts 2 Documentation - Security Bulletins - S2-052](https://cwiki.apache.org/confluence/display/WW/S2-052)

[Metasploit Modules Related To CVE-2017-9805](https://www.rapid7.com/db/modules/exploit/multi/http/struts2_rest_xstream)

[Oracle Security Alert Advisory - CVE-2017-9805](http://www.oracle.com/technetwork/security-advisory/alert-cve-2017-9805-3889403.html)
 