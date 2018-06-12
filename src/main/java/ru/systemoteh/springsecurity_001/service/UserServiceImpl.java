package ru.systemoteh.springsecurity_001.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import ru.systemoteh.springsecurity_001.dao.RoleDao;
import ru.systemoteh.springsecurity_001.dao.UserDao;
import ru.systemoteh.springsecurity_001.model.Role;
import ru.systemoteh.springsecurity_001.model.User;

import java.util.HashSet;
import java.util.Set;

/**
 * Implementation of {@link UserService} interface.
 */

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserDao userDao;

    @Autowired
    private RoleDao roleDao;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public void save(User user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        Set<Role> roles = new HashSet<>();
        roles.add(roleDao.getOne(2L));
        user.setRoles(roles);
        userDao.save(user);
    }

    @Override
    public User findByUsername(String username) {
        return userDao.findByUsername(username);
    }
}
