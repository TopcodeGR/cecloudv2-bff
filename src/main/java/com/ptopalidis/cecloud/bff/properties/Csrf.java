package com.ptopalidis.cecloud.bff.properties;

public enum Csrf {
    /**
     * Switches between DISABLED if statlessSessions is true (resource server) and SESSION otherwise (client)
     */
    DEFAULT,
    /**
     * Disables CSRF protection. The default value for resource servers, but <b>you should really not be doing that on a client!</b>
     */
    DISABLE,
    /**
     * Stores CSRF token in servlet session or reactive web-session. The default value for clients, which is just fine if your not querying it with a JS
     * application (written with Angular, React, Vue, etc.)
     */
    SESSION,
    /**
     * Stores CSRF in a XSRF-TOKEN cookie that is readable by JS apps. To be used when sessions are enabled and queries are issued with Angular, React, Vue,
     * etc.
     */
    COOKIE_ACCESSIBLE_FROM_JS
}