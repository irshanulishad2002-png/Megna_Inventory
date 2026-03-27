using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using megnaInventory.Models;

namespace megnaInventory.Controllers
{
    [Authorize(Roles = "Admin")]
    public class AdminController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ILogger<AdminController> _logger;

        private bool RestrictToDefaultAdmin()
        {
            return User.Identity?.Name == "admin@gmail.com";
        }

        public AdminController(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            ILogger<AdminController> logger)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _logger = logger;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            // Restrict access to only the default admin email as specified
            if (!RestrictToDefaultAdmin())
            {
                return Forbid();
            }

            ViewData["ActivePage"] = "Dashboard";
            var users = _userManager.Users.ToList();
            var model = new List<UserViewModel>();

            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                model.Add(new UserViewModel
                {
                    Id = user.Id,
                    Email = user.Email ?? string.Empty,
                    FullName = user.FullName,
                    Roles = roles.ToList(),
                    IsApproved = user.IsApproved,
                    PhoneNumber = user.PhoneNumber
                });
            }

            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> UserManagement()
        {
            // Restrict access to only the default admin email as specified
            if (!RestrictToDefaultAdmin())
            {
                return Forbid();
            }

            ViewData["ActivePage"] = "UserManagement";
            var users = _userManager.Users.ToList();
            var model = new List<UserViewModel>();

            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                model.Add(new UserViewModel
                {
                    Id = user.Id,
                    Email = user.Email ?? string.Empty,
                    FullName = user.FullName,
                    Roles = roles.ToList(),
                    IsApproved = user.IsApproved,
                    PhoneNumber = user.PhoneNumber
                });
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ApproveUser(string userId)
        {
            // Restrict access to only the default admin email as specified
            if (!RestrictToDefaultAdmin())
            {
                return Forbid();
            }

            var user = await _userManager.FindByIdAsync(userId);
            
            if (user != null)
            {
                user.IsApproved = true;
                await _userManager.UpdateAsync(user);
                _logger.LogInformation($"User {user.Email} approved by admin.");
                TempData["SuccessMessage"] = $"User {user.Email} has been approved successfully!";
            }
            else
            {
                TempData["ErrorMessage"] = "User not found.";
            }

            return RedirectToAction(nameof(UserManagement));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RejectUser(string userId)
        {
            // Restrict access to only the default admin email as specified
            if (!RestrictToDefaultAdmin())
            {
                return Forbid();
            }

            var user = await _userManager.FindByIdAsync(userId);
            
            if (user != null)
            {
                // Check if trying to reject admin
                var roles = await _userManager.GetRolesAsync(user);
                if (roles.Contains("Admin"))
                {
                    TempData["ErrorMessage"] = "Cannot reject an Admin user.";
                    return RedirectToAction(nameof(UserManagement));
                }

                user.IsApproved = false;
                await _userManager.UpdateAsync(user);
                _logger.LogInformation($"User {user.Email} rejected by admin.");
                TempData["SuccessMessage"] = $"User {user.Email} has been rejected.";
            }
            else
            {
                TempData["ErrorMessage"] = "User not found.";
            }

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteUser(string userId)
        {
            // Restrict access to only the default admin email as specified
            if (!RestrictToDefaultAdmin())
            {
                return Forbid();
            }

            var user = await _userManager.FindByIdAsync(userId);
            
            if (user != null)
            {
                // Check if trying to delete admin
                var roles = await _userManager.GetRolesAsync(user);
                if (roles.Contains("Admin"))
                {
                    TempData["ErrorMessage"] = "Cannot delete an Admin user.";
                    return RedirectToAction(nameof(Index));
                }

                await _userManager.DeleteAsync(user);
                _logger.LogInformation($"User {user.Email} deleted by admin.");
                TempData["SuccessMessage"] = $"User {user.Email} has been deleted successfully!";
            }
            else
            {
                TempData["ErrorMessage"] = "User not found.";
            }

            return RedirectToAction(nameof(Index));
        }

        [HttpGet]
        public async Task<IActionResult> EditUser(string userId)
        {
            // Restrict access to only the default admin email as specified
            if (!RestrictToDefaultAdmin())
            {
                return Forbid();
            }

            var user = await _userManager.FindByIdAsync(userId);
            
            if (user == null)
            {
                return NotFound();
            }

            var roles = await _userManager.GetRolesAsync(user);
            var allRoles = _roleManager.Roles.Select(r => r.Name).Where(n => n != null).Cast<string>().ToList();

            var model = new EditUserViewModel
            {
                Id = user.Id,
                Email = user.Email ?? string.Empty,
                FullName = user.FullName,
                PhoneNumber = user.PhoneNumber,
                SelectedRoles = roles.ToList(),
                AllRoles = allRoles,
                IsApproved = user.IsApproved
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditUser(EditUserViewModel model)
        {
            // Restrict access to only the default admin email as specified
            if (!RestrictToDefaultAdmin())
            {
                return Forbid();
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.FindByIdAsync(model.Id);
            
            if (user == null)
            {
                return NotFound();
            }

            user.Email = model.Email;
            user.FullName = model.FullName;
            user.PhoneNumber = model.PhoneNumber;
            user.IsApproved = model.IsApproved;

            var result = await _userManager.UpdateAsync(user);

            if (result.Succeeded)
            {
                // Update roles
                var currentRoles = await _userManager.GetRolesAsync(user);
                await _userManager.RemoveFromRolesAsync(user, currentRoles);
                await _userManager.AddToRolesAsync(user, model.SelectedRoles);

                _logger.LogInformation($"User {user.Email} updated by admin.");
                TempData["SuccessMessage"] = $"User {user.Email} has been updated successfully!";
                return RedirectToAction(nameof(UserManagement));
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            TempData["ErrorMessage"] = "Failed to update user. Please correct the errors.";
            return View(model);
        }
    }

    public class UserViewModel
    {
        public string Id { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string? FullName { get; set; }
        public List<string> Roles { get; set; } = new();
        public bool IsApproved { get; set; }
        public string? PhoneNumber { get; set; }
    }

    public class EditUserViewModel
    {
        public string Id { get; set; } = string.Empty;
        
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
        
        public string? FullName { get; set; }
        public string? PhoneNumber { get; set; }
        public bool IsApproved { get; set; }
        public List<string> SelectedRoles { get; set; } = new();
        public List<string> AllRoles { get; set; } = new();
    }
}
