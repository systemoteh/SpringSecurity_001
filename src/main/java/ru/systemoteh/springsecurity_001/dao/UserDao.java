package ru.systemoteh.springsecurity_001.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.systemoteh.springsecurity_001.model.User;

public interface UserDao extends JpaRepository<User, Long> {

    User findByUsername(String username);

}
