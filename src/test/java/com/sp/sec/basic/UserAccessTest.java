package com.sp.sec.basic;


import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest
public class UserAccessTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper mapper;

    @Autowired private PasswordEncoder passwordEncoder;

    UserDetails user1(){
        return User.builder()
                .username("user1")
                .password(passwordEncoder.encode("1234"))
                .roles("USER")
                .build();
    }
    UserDetails admin(){
        return User.builder()
                .username("admin")
                .password(passwordEncoder.encode("1234"))
                .roles("ADMIN")
                .build();
    }


    @DisplayName("1. user -> user 페이지를 접근 가능")
    @Test
//    @WithMockUser(username = "user1", roles = {"USER"})
    public void userToUserPageTest() throws Exception {

//        String resp = mockMvc.perform(get("/user"))   //  mockMvc.perform(get("/admin"))  // @WithMockUser 사용시
        String resp = mockMvc.perform(get("/user").with(user(user1())))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        SecurityMessage message = mapper.readValue(resp, SecurityMessage.class);
        Assertions.assertEquals("user page", message.getMessage());

    }

    @DisplayName("2. user -> admin 페이지를 접근 불가")
    @Test
//    @WithMockUser(username = "user1", roles = {"USER"})
    public void userToAdminPageTest() throws Exception {
//        mockMvc.perform(get("/admin"))  // @WithMockUser 사용시
        mockMvc.perform(get("/admin").with(user(user1())))
                .andExpect(status().is4xxClientError());
    }

    @DisplayName("3. admin -> user, admin 페이지 접근 가능")
    @Test
//    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void adminToUserAndAdminPageTest() throws Exception {
//        String userPageResp = mockMvc.perform(get("/user"))
        String userPageResp = mockMvc.perform(get("/user").with(user(admin())))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        SecurityMessage message1 = mapper.readValue(userPageResp, SecurityMessage.class);
        Assertions.assertEquals("user page", message1.getMessage());

//        String adminPageResp = mockMvc.perform(get("/admin"))
        String adminPageResp = mockMvc.perform(get("/admin").with(user(admin())))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        SecurityMessage message2 = mapper.readValue(adminPageResp, SecurityMessage.class);
        Assertions.assertEquals("admin page", message2.getMessage());

    }

    @DisplayName("4. user,admin -> login page 전부 접근 가능")
    @Test
    @WithAnonymousUser
    public void anonymousToLoginPageTest() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk());

    }

    @DisplayName("5. home Page 로그인사용자 접근 가능")
    @Test
    public void userAndAdminToHomePageTest() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().is3xxRedirection()); // 302 redirect to /login
        mockMvc.perform(get("/user"))
                .andExpect(status().is3xxRedirection()); // 302 redirect to /user
        mockMvc.perform(get("/admin"))
                .andExpect(status().is3xxRedirection()); // 302 redirect to /admin

    }
}
