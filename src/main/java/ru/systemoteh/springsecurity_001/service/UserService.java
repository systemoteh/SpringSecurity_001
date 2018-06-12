package ru.systemoteh.springsecurity_001.service;

import ru.systemoteh.springsecurity_001.model.User;

/**
 * Service class for {@link ru.systemoteh.springsecurity_001.model.User}
 */

public interface UserService {

    void save(User user);

    User findByUsername(String username);

}
