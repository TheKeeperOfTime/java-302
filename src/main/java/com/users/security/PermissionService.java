package com.users.security;

import static org.springframework.security.core.context.SecurityContextHolder.getContext;
import static com.users.security.Role.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import com.users.repositories.UserRepository;

@Service
public class PermissionService {

	@Autowired
	private UserRepository userRepo;

	private UsernamePasswordAuthenticationToken getToken() {
		return (UsernamePasswordAuthenticationToken) getContext().getAuthentication();
	}

	// I'm pretty sure that is authenticating the role of whoever is using it.
	// So, if it detects an ADMIN, it will give them ADMIN access.
	public boolean hasRole(Role role) {
		for (GrantedAuthority ga : getToken().getAuthorities()) {
			if (role.toString().equals(ga.getAuthority())) {
				return true;
			}
		}
		return false;
	}

	// This is saying that an ADMIN can edit USERS, but a USER can't edit
	// another USER
	public boolean canEditUser(long userId) {
		long currentUserId = userRepo.findByEmail(getToken().getName()).get(0).getId();
		return hasRole(ADMIN) || (hasRole(USER) && currentUserId == userId);
	}

}
