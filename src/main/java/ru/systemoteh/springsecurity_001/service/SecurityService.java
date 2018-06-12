package ru.systemoteh.springsecurity_001.service;

/**
 * Service for Security.
 */

public interface SecurityService {

    String findLoggedInUsername();

    void autoLogin(String username, String password);
}
