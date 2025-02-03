package com.cos.security1.repository;

import com.cos.security1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

//CRUD함수를 JPARepository가 들고 있음.
//@Repository라는 어노테이션 없어도 IoC 됨.
public interface UserRepository extends JpaRepository<User, Integer> {
}
