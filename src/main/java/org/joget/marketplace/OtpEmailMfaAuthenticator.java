package org.joget.marketplace;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.joget.plugin.property.service.PropertyUtil;
import org.joget.apps.app.lib.EmailTool;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.app.service.MfaAuthenticator;
import org.joget.commons.util.LogUtil;
import org.joget.commons.util.ResourceBundleUtil;
import org.joget.commons.util.SecurityUtil;
import org.joget.commons.util.SetupManager;
import org.joget.commons.util.StringUtil;
import org.joget.directory.dao.UserDao;
import org.joget.directory.dao.UserMetaDataDao;
import org.joget.directory.model.User;
import org.joget.directory.model.UserMetaData;
import org.joget.directory.model.service.DirectoryUtil;
import org.joget.directory.model.service.UserSecurity;
import org.joget.plugin.base.PluginManager;
import org.joget.plugin.base.PluginWebSupport;
import org.joget.workflow.model.service.WorkflowUserManager;

public class OtpEmailMfaAuthenticator extends MfaAuthenticator implements PluginWebSupport {
    private static final String KEY = "OTP_EMAIL";
    private static final String OTP_KEY = "OTP_EMAIL_CODE";
    private static final String EXPIRY_KEY = "OTP_EMAIL_EXPIRY";
    private static final String MESSAGE_PATH = "messages/OtpEmailMfaAuthenticator";

    @Override
    public String getName() {
        return "OTP Email MFA Authenticator";
    }

    @Override
    public String getVersion() {
        return "7.0.4";
    }

    @Override
    public String getDescription() {
        return "Time-based One-time Password Email Authentication";
    }

    @Override
    public String getLabel() {
        return "OTP Email MFA Authenticator";
    }

    @Override
    public String getClassName() {
        return getClass().getName();
    }

    @Override
    public String getPropertyOptions() {
        return AppUtil.readPluginResource(getClassName(), "/properties/OtpEmailMfaAuthenticator.json", null, true, MESSAGE_PATH);
    }

    @Override
    public String getKey() {
        return KEY;
    }

    @Override
    public String validateOtpUrl(String username) {
        UserMetaDataDao dao = (UserMetaDataDao) AppUtil.getApplicationContext().getBean("userMetaDataDao");

        String contextPath = AppUtil.getRequestContextPath();
        String encryptedUsername = SecurityUtil.encrypt(username);
        UserMetaData data = dao.getUserMetaData(username, KEY);
        String nonce = SecurityUtil.generateNonce(new String[]{encryptedUsername, data.getValue()}, 1);
        String url = null;

        try {
            url = contextPath + "/web/json/plugin/"+getClassName()+"/service?a=vp&u="+URLEncoder.encode(encryptedUsername, "UTF-8")+"&nonce="+URLEncoder.encode(nonce, "UTF-8");
        } catch (Exception e) {}

        return url;
    }

    @Override
    public String validateOtpMessage(String username) {
        return ResourceBundleUtil.getMessage("otpEmail.validate");
    }

    @Override
    public String activateOtpUrl(String username) {
        return AppUtil.getRequestContextPath() + "/web/json/plugin/"+getClassName()+"/service?a=eotp";
    }

    @Override
    public void webService(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        UserSecurity us = DirectoryUtil.getUserSecurity();
        setProperties(us.getProperties());

        String content = "";
        Map model = new HashMap();
        model.put("request", request);

        String action = request.getParameter("a");
        if (action != null) {
            if ("eotp".equals(action)) {
                content = wsEnableOtpAuthHandle(model, request, response);
            } else if ("eotps".equals(action)) {
                content = wsEnableOtpAuthSubmitHandle(model, request, response);
            } else if ("vp".equals(action)) {
                content = wsVerifyPinHandle(model, request, response);
            } else if ("vps".equals(action)) {
                content = wsVerifyPinSubmitHandle(model, request, response);
            }
        }

        if (content != null && !content.isEmpty()) {
            String css = AppUtil.getUserviewThemeCss();
            String contextPath = request.getContextPath();

            if(css.isEmpty()){
                css = "<link rel=\"stylesheet\" type=\"text/css\" href=\"" + contextPath + "/css/v7.css\"/>";
                css+= "<link rel=\"stylesheet\" type=\"text/css\" href=\"" + contextPath + "/css/console_custom.css\"/>";
            }

            content = css + content;

            response.setContentType("text/html");
            PrintWriter writer = response.getWriter();
            writer.write(content);
        } else {
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
        }
    }

    
    private int getValidityMinutes() {
        int minute = 5; 

        try {
            Object mpfObj = this.getProperty("mpfAuthenticator");
            if (mpfObj instanceof Map) {
                Object propsObj = ((Map) mpfObj).get("properties");
                if (propsObj instanceof Map) {
                    Object v = ((Map) propsObj).get("validity");
                    if (v != null) {
                        minute = Integer.parseInt(v.toString().trim());
                    }
                }
            }
        } catch (Exception e) {
        }
        if (minute < 1) {
            minute = 1;
        }

        return minute;
    }

    protected String wsEnableOtpAuthHandle(Map model, HttpServletRequest request, HttpServletResponse response) throws UnsupportedEncodingException {
        WorkflowUserManager wum = (WorkflowUserManager) AppUtil.getApplicationContext().getBean("workflowUserManager");
        String username = wum.getCurrentUsername();

        UserDao userDao = (UserDao) AppUtil.getApplicationContext().getBean("userDao");
        User user = userDao.getUser(username);

        UserMetaDataDao dao = (UserMetaDataDao) AppUtil.getApplicationContext().getBean("userMetaDataDao");

        //delete existing usermedata before continue
        dao.deleteUserMetaData(username, OTP_KEY);
        dao.deleteUserMetaData(username, EXPIRY_KEY);
        dao.deleteUserMetaData(username, KEY);

        //create new usermedata
        String pin = getRandomOTP();

        UserMetaData umOTP = new UserMetaData();
        umOTP.setUsername(username);
        umOTP.setKey(OTP_KEY);
        umOTP.setValue(StringUtil.md5(pin));
        
        dao.addUserMetaData(umOTP);

        int minute = getValidityMinutes();
        long expiryTime = System.currentTimeMillis() + (long) minute * 60_000L;

        UserMetaData umExpiry = new UserMetaData();
        umExpiry.setUsername(username);
        umExpiry.setKey(EXPIRY_KEY);
        umExpiry.setValue(Long.toString(expiryTime));
        dao.addUserMetaData(umExpiry);

        if (wum.isCurrentUserAnonymous()) {
            return getTemplate("unauthorized", model);
        }

        Map<String, String> variables = new HashMap<>();
        variables.put("pin", pin);
        variables.put("validity", String.valueOf(minute));

        // send first time activation email
        Map mpfProperties = (HashMap) ((HashMap) this.getProperty("mpfAuthenticator")).get("properties");
        sendEmail(user, (String) mpfProperties.get("subject"), (String) mpfProperties.get("message"), variables);

        return getTemplate("enableOtpAuth", model);
    }

    protected String generateOTP(String username){
        String otp = getRandomOTP();

        UserMetaDataDao dao = (UserMetaDataDao) AppUtil.getApplicationContext().getBean("userMetaDataDao");

        //delete existing usermedata before continue
        dao.deleteUserMetaData(username, EXPIRY_KEY);
        dao.deleteUserMetaData(username, OTP_KEY);

        UserMetaData umOTP = new UserMetaData();
        umOTP.setUsername(username);
        umOTP.setKey(OTP_KEY);
        umOTP.setValue(StringUtil.md5(otp));
        
        dao.addUserMetaData(umOTP);

        int minute = getValidityMinutes();
        long expiryTime = System.currentTimeMillis() + (long) minute * 60_000L;

        UserMetaData umExpiry = new UserMetaData();
        umExpiry.setUsername(username);
        umExpiry.setKey(EXPIRY_KEY);
        umExpiry.setValue(Long.toString(expiryTime));
        dao.addUserMetaData(umExpiry);

        return otp;
    }

    protected boolean validateOTP(String username, String code) {
        try {
            UserMetaDataDao dao = (UserMetaDataDao) AppUtil.getApplicationContext().getBean("userMetaDataDao");

            UserMetaData umOtp = dao.getUserMetaData(username, OTP_KEY);
            UserMetaData umExp = dao.getUserMetaData(username, EXPIRY_KEY);

            if (umOtp == null || umExp == null || umOtp.getValue() == null || umExp.getValue() == null) {
                return false;
            }

            String savedOTP = umOtp.getValue();
            long generatedExpiry = Long.parseLong(umExp.getValue());
            long currentTime = System.currentTimeMillis();

            return savedOTP.equals(StringUtil.md5(code)) && generatedExpiry > currentTime;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public void updateUserProfileProcessing(String username, HttpServletRequest request) {
        String submittedValue = request.getParameter(getKey().toLowerCase());

        if (submittedValue != null && !submittedValue.isEmpty()
                && !PropertyUtil.PASSWORD_PROTECTED_VALUE.equals(submittedValue)) {
            // Only allow activation when the current session has verified OTP for this user
            String sessionKey = "OTP_EMAIL_ACTIVATION_VERIFIED_" + username;
            Boolean verified = (Boolean) request.getSession().getAttribute(sessionKey);
            if (verified == null || !verified) {
                LogUtil.warn(getClassName(), "Blocked unauthorized MFA activation attempt for user: " + username);
                return;
            }
            request.getSession().removeAttribute(sessionKey);
        }
        super.updateUserProfileProcessing(username, request);
    }

    protected String getRandomOTP() {
        Random rnd = new Random();
        int number = rnd.nextInt(999999);
        return String.format("%06d", number);
    }

    protected String wsEnableOtpAuthSubmitHandle(Map model, HttpServletRequest request, HttpServletResponse response) throws UnsupportedEncodingException {
        WorkflowUserManager wum = (WorkflowUserManager) AppUtil.getApplicationContext().getBean("workflowUserManager");
        String username = wum.getCurrentUsername();

        UserMetaDataDao dao = (UserMetaDataDao) AppUtil.getApplicationContext().getBean("userMetaDataDao");
        UserMetaData data = dao.getUserMetaData(username, KEY);

        // only allow POST
        if (!"POST".equalsIgnoreCase(request.getMethod()) || wum.isCurrentUserAnonymous() || data != null) {
            return getTemplate("unauthorized", model);
        }

        String pin = request.getParameter("pin");

        if (pin != null && validateOTP(username, pin)) {
            request.getSession().setAttribute("OTP_EMAIL_ACTIVATION_VERIFIED_" + username, Boolean.TRUE);
            return "<script>parent.updateMFa(\"enabled\");</script>";
        } else {
            model.put("error", ResourceBundleUtil.getMessage("otpEmail.invalid"));
        }

        return getTemplate("enableOtpAuth", model);
    }

    protected String wsVerifyPinHandle(Map model, HttpServletRequest request, HttpServletResponse response) {
        Map mpfProperties = (HashMap) ((HashMap) this.getProperty("mpfAuthenticator")).get("properties");

        String tempusername = request.getParameter("u");
        if (tempusername != null) {
            UserMetaDataDao dao = (UserMetaDataDao) AppUtil.getApplicationContext().getBean("userMetaDataDao");

            String username = SecurityUtil.decrypt(tempusername);
            String nonce = request.getParameter("nonce");
            UserMetaData usecret = dao.getUserMetaData(username, KEY);

            UserDao userDao = (UserDao) AppUtil.getApplicationContext().getBean("userDao");
            User user = userDao.getUser(username);

            if (usecret == null || !SecurityUtil.verifyNonce(nonce, new String[]{tempusername, usecret.getValue()})) {
                return getTemplate("unauthorized", model);
            }

            String pin = generateOTP(username);

            Map<String, String> variables = new HashMap<>();
            variables.put("pin", pin);
            variables.put("validity", String.valueOf(getValidityMinutes()));

            // send login verification code
            sendEmail(user, (String) mpfProperties.get("subject"), (String) mpfProperties.get("message"), variables);

            model.put("username", tempusername);
            model.put("nonce", nonce);
            try {
                model.put("url", AppUtil.getRequestContextPath() + "/web/json/plugin/" + getClassName() + "/service?a=vps&u="
                        + URLEncoder.encode(tempusername, "UTF-8") + "&nonce=" + URLEncoder.encode(nonce, "UTF-8"));
            } catch (UnsupportedEncodingException ex) {
                // ignore
            }
        }

        return getTemplate("verifyPin", model);
    }

    protected String wsVerifyPinSubmitHandle(Map model, HttpServletRequest request, HttpServletResponse response) throws IOException {
        String tempusername = request.getParameter("u");
        if (tempusername != null) {
            UserMetaDataDao dao = (UserMetaDataDao) AppUtil.getApplicationContext().getBean("userMetaDataDao");

            String username = SecurityUtil.decrypt(tempusername);
            String nonce = request.getParameter("nonce");
            UserMetaData usecret = dao.getUserMetaData(username, KEY);

            if (usecret == null || !SecurityUtil.verifyNonce(nonce, new String[]{tempusername, usecret.getValue()})) {
                return getTemplate("unauthorized", model);
            }

            try {
                model.put("url", AppUtil.getRequestContextPath() + "/web/json/plugin/"+getClassName()+"/service?a=vps&u="+URLEncoder.encode(tempusername, "UTF-8")+"&nonce="+URLEncoder.encode(nonce, "UTF-8"));
            } catch (UnsupportedEncodingException ex) {
            }

            String pin = request.getParameter("pin");
            if (pin != null && validateOTP(username, pin)) {
                return loginUser(username);
            } else {
                model.put("error", ResourceBundleUtil.getMessage("otpEmail.invalid"));
            }
        }

        return getTemplate("verifyPin", model);
    }

    @Override
    protected String getTemplate(String template, Map model) {
        // display license page
        PluginManager pluginManager = (PluginManager) AppUtil.getApplicationContext().getBean("pluginManager");
        String content = pluginManager.getPluginFreeMarkerTemplate(model, getClass().getName(), "/templates/" + template + ".ftl", MESSAGE_PATH);
        return content;
    }

    public boolean isSmtpNotConfigured() {
        String smtpHost = getPropertyString("host");
        SetupManager setupManager = (SetupManager)AppUtil.getApplicationContext().getBean("setupManager");
        String sysHost = setupManager.getSettingValue("smtpHost");
        return ((smtpHost == null || smtpHost.isEmpty()) && (sysHost == null || sysHost.isEmpty()));
    }

    protected String populateEmailData(String content, User user, Map<String, String> variables) {
        if (user != null) {
            content = content.replace("#username#", (user.getUsername() != null) ? user.getUsername() : "");
            content = content.replace("{username}", (user.getUsername() != null) ? user.getUsername() : "");
            content = content.replace("#firstName#", (user.getFirstName() != null) ? user.getFirstName() : "");
            content = content.replace("#lastName#", (user.getLastName() != null) ? user.getLastName() : "");
            content = content.replace("#email#", (user.getEmail() != null) ? user.getEmail() : "");
            content = content.replace("#password#", (user.getConfirmPassword() != null) ? user.getConfirmPassword() : "");
            content = content.replace("#locale#", (user.getLocale() != null) ? user.getLocale() : "");
            content = content.replace("#timeZone#", (user.getTimeZoneLabel() != null) ? user.getTimeZoneLabel() : "");
            content = content.replace("#active#", (user.getActive() != null) ? user.getActive().toString() : "");
        }

        if (variables != null && !variables.isEmpty()) {
            for (String name : variables.keySet()) {
                content = content.replace("#" + name + "#", variables.get(name));
            }
        }

        content = AppUtil.processHashVariable(content, null, null, null);
        return content;
    }

    protected void sendEmail(User user, String subject, String message, Map<String, String> variables) {
        if (isSmtpNotConfigured()) {
            LogUtil.warn(EmailTool.class.getName(), "Send email to user " + user.getUsername() + " failed, SMTP host not configured");
        } else {
            try {
                String emailSubject = populateEmailData(subject, user, variables);
                if (emailSubject != null) {
                    emailSubject = emailSubject.replace("\n", "").replace("\r", "");
                }

                Map emailProp = new HashMap();
                emailProp.put("host", getPropertyString("host"));
                emailProp.put("port", getPropertyString("port"));
                emailProp.put("security", getPropertyString("security"));
                emailProp.put("username", getPropertyString("username"));
                emailProp.put("password", getPropertyString("password"));
                emailProp.put("from", getPropertyString("from"));
                emailProp.put("cc", getPropertyString("cc"));
                emailProp.put("subject", emailSubject);
                emailProp.put("isHtml", getPropertyString("isHtml"));
                emailProp.put("toSpecific", user.getEmail());
                emailProp.put("message", populateEmailData(message, user, variables));

                EmailTool tool = new EmailTool();
                tool.execute(emailProp);
            } catch (Exception e) {
                LogUtil.error(EmailTool.class.getName(), e, null);
            }
        }
    }
}
