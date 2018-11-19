## Shiro简介

- Apache的开源安全框架
- 提供认证、授权、会话管理、安全加密、缓存管理等等相关的功能

## Shiro与Spring Security对比

|    Shiro     | Spring Security |
| :----------: | :-------------: |
|  简单，灵活  |   复杂，笨重    |
| 可脱离Spring | 不可脱离Spring  |
|   粒度较粗   |    粒度更细     |

## 整体架构

![](http://shiro.apache.org/assets/images/ShiroArchitecture.png)

主要分为两大块 `Subject` 和`Security Manager`

### Subject

可以理解为当前的操作用户

### Security Manager

是Shiro的核心，她管理着其他组件的实例。它包含下面这些组件

- Authenticator(认证)

  我们应用的认证器，管理登录，登出

- Authorizer(授权)

  我们应用的授权器，主要赋予Subject(当前的操作用户)有哪些权限

- Session Manager

  Shiro自己实现的一套管理机制，可以在不借用任何web容器下使用session，下面的Session Dao是提供了一些Session的操作，主要有增删改查

- Cache Manager

  缓存管理器，主要用于缓存角色数据和权限数据

- Realms

  充当了 Shiro 与应用安全数据间的“桥梁”或者“连接器”，Shiro通过它来从数据库中获取认证数据、角色数据和权限数据。

- Cryptography(加密)

  Shiro提供的加密工具，可以使用她非常快捷，方便的来做数据加密

- 更多信息查看 [官方架构文档](http://shiro.apache.org/architecture.html)

## 认证

更多信息请查看 [认证官方文档](http://shiro.apache.org/authentication.html)

### 认证过程

```flow
start=>operation: 创建SecurityManager
login=>operation: Subject提交认证请求
securityManagerAuthenticator=>operation: SecurityManager认证
Authenticator=>operation: Authenticator认证
end=>operation: Realm认证
start->login(right)->securityManagerAuthenticator(right)->Authenticator(right)->end
```

1. 创建Shiro的核心SecurityManager对象，构建Shiro环境
2. Subject提交认证请求，相当于登录操作，实际上会提交到SecurityManager进行认证
3. SecurityManager则会使用父类属性authenticator进行认证
4. Authenticator则会先获取所有的Realm，然后会查询Cache中是否存在认证信息没有，则会去Realm中认证。多个Realm会循环认证，都是先查询Cache然后查询Realm
5. Realm会查询数据库里面的数据，它会抛出一定的异常，代表认证失败

## 授权

更多信息请查看 [授权官方文档](http://shiro.apache.org/authorization.html)

### 授权过程

```flow
start=>operation: 创建SecurityManager
authorizer=>operation: Subject授权
securityManagerAuthorizer=>operation: SecurityManager授权
Authorize=>operation: Authorizer授权
end=>operation: Realm获取角色权限数据
start->authorizer->securityManagerAuthorizer(right)->Authorize(right)->end
```

1. 创建Shiro的核心SecurityManager对象，构建Shiro环境
2. 在需要验证权限的时候，会调用Subject授权方法，最后还是会调用SecurityManager进行授权
3. SecurityManager授权会使用父类属性authorizer进行授权
4. authorizer授权会去Cache中获取，如果没有则会调用SecurityManager中指定的Realm进行获取
5. Realm就会直接从数据库获取角色和权限数据

## Realm

更多信息请查看 [Realm官方文档](http://shiro.apache.org/realm.html)

### 内置Realm

#### IniRealm

从配置文件中获取用户、角色和权限数据

```ini
[main]
# 提供了对根对象 securityManager 及其依赖的配置
securityManager=org.apache.shiro.mgt.DefaultSecurityManager

[users]
# 提供了对用户/密码及其角色的配置
# username=password,role1,role2
admin=123456,admin

[roles]
# 提供了角色及权限之间关系的配置
# role=permission1,permission2
admin=c,r,u,d

[urls]
# 用于 web，提供了对 web url 拦截相关的配置，
# url=拦截器[参数]，拦截器
/index.html=anon
/admin/**=authc, roles[admin], perms["permission1"]
```

SecurityManager中注入 `org.apache.shiro.realm.text.IniRealm` 类并指定配置文件路径即可

#### JdbcRealm

从数据库中获取用户、角色和权限数据。但是该Realm有一些默认的查询语句，并且指定了表名和字段名，虽然可以修改他默认的sql语句，但是不够方便。因此还是自定义Realm方便一些。

SecurityManager中注入 `org.apache.shiro.realm.jdbc.JdbcRealm` 类并创建对应的表和字段即可

### 自定义Realm

创建类继承`AuthorizingRealm`并实现其方法，之后在SecurityManager中注入该类即可。

实现方法如下(该实现方法采用MybatisPlus为持久层框架)

```java
	/** 授权 */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        User user = (User)principalCollection.getPrimaryPrincipal();
        List<Role> roleList = userService.selectAllRole(user);
        List<Permission> permissionList = userService.selectAllPermissionByUid(user);
        if(!roleList.isEmpty()){
            roleList.forEach(e->{
                authorizationInfo.addRole(e.getRid().toString());
            });
        }
        if(!permissionList.isEmpty()){
            permissionList.forEach(e->{
                authorizationInfo.addStringPermission(e.getPermissionCode());
            });
        }
        return authorizationInfo;
    }

    /** 认证 */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        String username = (String)authenticationToken.getPrincipal();
        User user = userService.selectOne(new EntityWrapper<User>().eq("username", username));
        if(Objects.isNull(user)){
            return null;
        }
        if(user.getStatus() == 2){
            throw new LockedAccountException();
        }
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(user,user.getPassword(),this.getName());
        return authenticationInfo;
    }
```

## 安全加密

### Shiro散列配置

#### HashedCredentialsMatcher

这是Shiro的一个加密工具类，可以设置加密算法和加密算法的加密次数

> hashAlgorithm	该属性指定加密的算法
>
> hashIterations	该属性指定加密算法的加密次数

#### 自定义Realm中使用散列

直接在Realm中配置HashedCredentialsMatcher并设置加密算法和次数即可

Springboot中配置加密如下

```java
	@Bean(name = "hashedCredentialsMatcher")
    public HashedCredentialsMatcher hashedCredentialsMatcher() {
        HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
        hashedCredentialsMatcher.setHashAlgorithmName("MD5");// 散列算法:这里使用MD5算法;
        hashedCredentialsMatcher.setHashIterations(2);// 散列的次数，比如散列两次，相当于md5(md5(""));
        return hashedCredentialsMatcher;
    }

	@Bean
    public ShiroRealm shiroRealm(@Qualifier("hashedCredentialsMatcher") HashedCredentialsMatcher matcher){
        ShiroRealm shiroRealm = new ShiroRealm();
        // 设置密码凭证匹配器
        shiroRealm.setCredentialsMatcher(matcher);
        return shiroRealm;
    }
```

#### 加盐

加盐是为了让密码更加难以识破，一般都是生成一个随机数来和密码一起使用。

直接在Realm认证方法中添加一个参数即可

```java
SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(user,user.getPassword(),ByteSource.Util.bytes(user.getSalt()),this.getName());
```

下面代码为生成随机盐值和通过盐加密后的密码

```java
//随机数生成器
RandomNumberGenerator randomNumberGenerator = new SecureRandomNumberGenerator();
String salt = randomNumberGenerator.nextBytes().toHex();
String password = new SimpleHash("MD5",user.getPassword(),ByteSource.Util.bytes(salt),2).toHex();
```

## Shiro内置拦截器

认证过滤器

> org.apache.shiro.web.filter.authc.AuthenticatingFilter

|  过滤器   |           说明           |
| :-------: | :----------------------: |
|   anon    | 不需要认证，直接可以访问 |
| authBasic |      httpBasic认证       |
|   authc   |     需要认证才能访问     |
|   user    | 需要当前存在用户才能访问 |
|  logout   |           登出           |

授权过滤器

> org.apache.shiro.web.filter.authz.AuthorizationFilter

| 过滤器 |           说明           |
| :----: | :----------------------: |
| perms  | 具备相关的权限才可以访问 |
| roles  | 具备相关的角色才可以访问 |
|  ssl   |  安全协议，也就是https   |
|  port  | 访问指定的端口才可以访问 |

更多过滤器查看 [过滤器官方文档](http://shiro.apache.org/web.html#Web-DefaultFilters)

在ShiroFilterFactoryBean中设置属性 `filterChainDefinitionMap`即可，注意他是链式过滤的，就是说是安装从上到下进行过滤的。下面给出一个Springboot的例子

```java
	@Bean
    public ShiroFilterFactoryBean shirFilter(SecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        //拦截器
        Map<String,String> filterChainDefinitionMap = new LinkedHashMap<>();
        filterChainDefinitionMap.put("/authc","anon");
        filterChainDefinitionMap.put("/login","anon");
        // 过滤swagger
        filterChainDefinitionMap.put("/swagger-ui.html", "anon");
        filterChainDefinitionMap.put("/swagger-resources/**", "anon");
        filterChainDefinitionMap.put("/v2/api-docs/**", "anon");
        filterChainDefinitionMap.put("/webjars/springfox-swagger-ui/**", "anon");
        //过滤druid
        filterChainDefinitionMap.put("/druid/**","anon");

        //配置退出 过滤器,其中的具体的退出代码Shiro已经替我们实现了
        filterChainDefinitionMap.put("/logout", "logout");
        //过滤链定义，从上向下顺序执行，一般将/**放在最为下边
        //authc:所有url都必须认证通过才可以访问; anon:所有url都都可以匿名访问
        filterChainDefinitionMap.put("/**", "authc");
        // 如果不设置默认会自动寻找Web工程根目录下的"/login.jsp"页面
        shiroFilterFactoryBean.setLoginUrl("/authc");
        // 登录成功后要跳转的链接
        //shiroFilterFactoryBean.setSuccessUrl("/index");
        //未授权界面;用户访问未对其授权的资源时，所显示的连接 但是使用注解的话这段不起作用，需要使用异常处理器重定向页面
        shiroFilterFactoryBean.setUnauthorizedUrl("/unauthorized");
        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return shiroFilterFactoryBean;
    }
```

## 自定义拦截器

需要认证拦截就继承 `org.apache.shiro.web.filter.authc.AuthenticatingFilter` 类，重写父类中的方法。

需要授权拦截就继承 `org.apache.shiro.web.filter.authz.AuthorizationFilter`  类，重写父类中的方法。

写好拦截器后需要注入到ShiroFilter中即可，更多过滤器信息请直接查看源码进行了解

## 会话管理

Shiro自己实现了一套Session管理体系，他可以使我们在不介入Web容器和Servlet下使用Session。

更多信息查看 [会话管理官方文档](http://shiro.apache.org/session-management.html)

### SessionManager

Shiro提供的一个Session管理器

### SessionDAO

提供Session的增删改查操作

### Redis实现Session共享

1. 自定义SessionDAO，继承 `org.apache.shiro.session.mgt.eis.AbstractSessionDAO` 并重写其方法，主要包括基本增删改查以及获取所有活动的Session
2. 自定义SessionManager，创建RedisSessionManager类继承 `org.apache.shiro.web.session.mgt.DefaultWebSessionManager`重写`retrieveSession`方法，可以设置为先从Request中获取，取不到则从Redis中获取。这样可以减轻Redis的压力
3. 将自定义SessionManager注入到SecurityManager中

## 缓存管理

CacheManager，主要用来缓存角色数据和权限数据，这样就可以不用每次授权的时候都要去数据库查询角色和权限信息。主要是通过CacheManager和Cache这两个接口来管理Cache

更多缓存信息请查看 [缓存官方文档](http://shiro.apache.org/caching.html)

### Redis实现缓存管理

1. 自定义RedisCache类实现 `org.apache.shiro.cache.Cache<K,V>`接口并实现相应的方法

2. 自定义CacheManager类实现 `org.apache.shiro.cache.CacheManager`接口并实现相应的方法
3. 将自定义RedisCache注入到自定义的CacheManager中
4. 再将自定义CacheManager注入到SecurityManager中

## 自动登录

1. 创建 `org.apache.shiro.web.servlet.SimpleCookie`对象，并设置Cookie名称和过期时间
2. 创建 `org.apache.shiro.web.mgt.CookieRememberMeManager`对象，并设置Cookie为SimpleCookie对象
3. 将CookieRememberMeManager对象注入到SecurityManager的属性 `rememberMeManager` 中
4. 在认证或登录的时候创建的 `org.apache.shiro.authc.UsernamePasswordToken` 对象中设置`rememberMe`属性，这是一个boolean值

## 示例项目

> [码云](https://gitee.com/wbsxch/shiro)