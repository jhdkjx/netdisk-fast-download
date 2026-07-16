package cn.qaiu.lz.web.model;

import cn.qaiu.db.ddl.Constraint;
import cn.qaiu.db.ddl.Length;
import cn.qaiu.db.ddl.Table;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;

import java.util.Date;

/**
 * 捐赠账号实体
 * 用户捐赠的网盘认证信息，解析时随机选择使用
 */
@Data
@Table("donated_account")
public class DonatedAccount {

    private static final long serialVersionUID = 1L;

    @Constraint(autoIncrement = true, notNull = true)
    private Long id;

    @Length(varcharSize = 16)
    @Constraint(notNull = true)
    private String panType; // 网盘类型: QK, UC, FJ, IZ, YE

    @Length(varcharSize = 32)
    @Constraint(notNull = true)
    private String authType; // 认证类型: cookie, accesstoken, authorization, password, custom

    @Length(varcharSize = 128)
    private String username; // 用户名

    @Length(varcharSize = 128)
    private String password; // 密码

    @Length(varcharSize = 4096)
    private String token; // Cookie/Token

    @Length(varcharSize = 64)
    private String remark; // 备注

    @Length(varcharSize = 64)
    private String ip; // 捐赠者IP

    @Constraint(notNull = true, defaultValue = "true")
    private Boolean enabled = true; // 是否启用

    @Constraint(notNull = true, defaultValue = "0")
    private Integer failCount = 0; // 失败次数，达到阈值自动禁用

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date createTime = new Date();
}
