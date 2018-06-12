-- Schema spring_security_001
CREATE SCHEMA `spring_security_001` ;

-- Table: users
CREATE TABLE spring_security_001.users (
  id       INT          NOT NULL AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(255) NOT NULL,
  password VARCHAR(255) NOT NULL
)
  ENGINE = InnoDB;

-- Table: roles
CREATE TABLE spring_security_001.roles (
  id   INT          NOT NULL AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL
)
  ENGINE = InnoDB;

-- Table for mapping user and roles: user_roles
CREATE TABLE spring_security_001.user_roles (
  user_id INT NOT NULL,
  role_id INT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users (id),
  FOREIGN KEY (role_id) REFERENCES roles (id),
  UNIQUE (user_id, role_id)
)
  ENGINE = InnoDB;

-- Insert data
INSERT INTO spring_security_001.users VALUES (1, 'systemoteh', '$2a$04$VKX6zZ9WIrKIkNgj05jEaOn1CoQUg3cPQXs2Sodfqw41QEhnheqJC');
INSERT INTO spring_security_001.roles VALUES (1, 'ROLE_USER');
INSERT INTO spring_security_001.roles VALUES (2, 'ROLE_ADMIN');
INSERT INTO spring_security_001.user_roles VALUES (1, 2);