// Expected: CWE-862 missing-auth finding
// Spring controller with unauthenticated admin endpoint
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    // No @PreAuthorize or @Secured — should trigger CWE-862
    @GetMapping("/users")
    public List<User> listUsers() {
        return userRepository.findAll();
    }

    @PostMapping("/users")
    public User createUser(@RequestBody User user) {
        return userRepository.save(user);
    }
}
