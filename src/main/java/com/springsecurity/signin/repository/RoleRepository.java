package com.springsecurity.signin.repository;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.springsecurity.signin.models.ERole;
import com.springsecurity.signin.models.Role;



@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
	  Optional<Role> findByName(ERole name);

}
