// Expected: CWE-639 idor finding
// Spring controller with IDOR — uses request param directly without ownership check
@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    @Autowired
    private AccountRepository accountRepository;

    @GetMapping("/{id}")
    public Account getAccount(@PathVariable Long id) {
        // No ownership check — any authenticated user can access any account
        return accountRepository.findById(id).orElseThrow();
    }
}
