package top.qingrang;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.junit.Test;
import java.util.ArrayList;
import java.util.List;

public class ShiroTest {

    /**
     * 获取 Subject 对象
     * Shiro 这个安全框架下， Subject 就是当前用户
     * @return Subject 对象
     */
    private static Subject getSubject(User user) {
        // 加载配置文件，并获取工厂
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("src/main/shiro.ini");
        // 获取安全管理者实例
        SecurityManager sm = factory.getInstance();
        // 将安全管理者放入全局对象
        SecurityUtils.setSecurityManager(sm);
        // 全局对象通过安全管理者生成 Subject 对象
        Subject subject = SecurityUtils.getSubject();

        return subject;
    }

    /**
     * 是否包含角色
     * @param user 用户
     * @param role 角色
     * @return
     */
    private static boolean hasRole(User user, String role) {
        Subject subject = getSubject(user);
        return subject.hasRole(role);
    }

    /**
     * 是否拥有权限
     * @param user 用户
     * @param permit 权限
     * @return
     */
    private static boolean isPermitted(User user, String permit) {
        Subject subject = getSubject(user);
        return subject.isPermitted(permit);
    }

    /**
     * 登录
     * @param user
     * @return
     */
    private static boolean login(User user) {
        // 获取 Subject 对象
        Subject subject = getSubject(user);

        //如果已经登录过了，退出
        if(subject.isAuthenticated())
            subject.logout();

        //封装用户的数据
        UsernamePasswordToken token = new UsernamePasswordToken(user.getName(), user.getPassword());
        try {
            //将用户的数据 token 最终传递到 Realm 中进行对比
            subject.login(token);
        } catch (AuthenticationException e) {
            //验证错误
            return false;
        }

        return subject.isAuthenticated();
    }

    /**
     * 用户们：创建了 3 个用户，前两个能在 shiro.ini 中找到，第 3 个找不到
     * @return 用户列表
     */
    private static List<User> createUser(){
        User z3admin = new User();
        z3admin.setName("z3admin");
        z3admin.setPassword("12345");

        User l4productManager = new User();
        l4productManager.setName("l4productManager");
        l4productManager.setPassword("abcde");

        User w5 = new User();
        w5.setName("w5");
        w5.setPassword("111");

        List<User> userList = new ArrayList<>();
        userList.add(z3admin);
        userList.add(l4productManager);
        userList.add(w5);

        return userList;
    }

    /**
     * 角色们：创建了两个角色，管理员，产品经理
     * @return 角色列表
     */
    private static List<String> createRole() {
        String roleAdmin = "admin"; // 管理员
        String roleProductManager ="productManager"; // 产品经理

        List<String> roleList = new ArrayList<>();
        roleList.add(roleAdmin);
        roleList.add(roleProductManager);
        return roleList;
    }

    /**
     * 权限们：创建了两种权限，产品管理，订单管理
     * @return
     */
    private static List<String> createPermit(){
        String permitAddProduct = "addProduct";
        String permitAddOrder = "addOrder";

        List<String> permitList = new ArrayList<>();
        permitList.add(permitAddProduct);
        permitList.add(permitAddOrder);

        return permitList;
    }

    @Test
    public void Test() {
        List<User> userList = createUser();
        List<String> roleList = createRole();
        List<String> permitList = createPermit();

        // ====================== 测试登录 =========================
        //登陆每个用户
        System.out.println("------------- 测试登录的分割线 -------------");
        for (User user : userList) {
            if(login(user))
                System.out.printf(user.getName() + " - 登陆成功，用的密码是：" + user.getPassword() + "\n");
            else
                System.out.printf(user.getName() + " - 登录失败，用的密码是：" + user.getPassword() + "\n");
        }


        // ====================== 测试是否包含角色 ====================
        // 判断能够登录的用户是否拥有某个角色
        System.out.println("-------------- 测试是否包含角色的分割线 -------------");
        for (User user : userList) {
            for (String role : roleList) {
                if(login(user)) {
                    if(hasRole(user, role))
                        System.out.printf(user.getName() + " - 拥有角色：" + role + "\n");
                    else
                        System.out.printf(user.getName() + " - 不拥有角色：" + role + "\n");
                }
            }
        }

        // ======================= 测试是否拥有权限 ==================
        // 判断能够登录的用户，是否拥有某种权限
        System.out.println("-------------- 测试是否拥有权限的分割线 -------------");
        for (User user : userList) {
            for (String permit : permitList) {
                if(login(user)) {
                    if(isPermitted(user, permit))
                        System.out.printf(user.getName() + " - 拥有权限: " + permit + "\n");
                    else
                        System.out.printf(user.getName() + " - 不拥有权限: " + permit + "\n");
                }
            }
        }
    }
}
