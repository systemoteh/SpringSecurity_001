package ru.systemoteh.springsecurity_001.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.systemoteh.springsecurity_001.model.Role;

public interface RoleDao extends JpaRepository<Role, Long> {

}