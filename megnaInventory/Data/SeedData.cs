using Microsoft.AspNetCore.Identity;
using megnaInventory.Models;

namespace megnaInventory.Data
{
    public static class SeedData
    {
        public static async Task InitializeAsync(IServiceProvider serviceProvider)
        {
            using (var scope = serviceProvider.CreateScope())
            {
                var services = scope.ServiceProvider;
                var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("SeedData");

                try
                {
                    var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
                    var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();

                    // Create roles if they don't exist
                    string[] roleNames = { "Admin", "Inventory Manager", "Sales Person", "Supplier" };
                    
                    foreach (var roleName in roleNames)
                    {
                        if (!await roleManager.RoleExistsAsync(roleName))
                        {
                            await roleManager.CreateAsync(new IdentityRole(roleName));
                            logger.LogInformation($"Role '{roleName}' created successfully.");
                        }
                    }

                    // Create default admin user
                    var adminEmail = "admin@gmail.com";
                    var adminUser = await userManager.FindByEmailAsync(adminEmail);

                    if (adminUser == null)
                    {
                        adminUser = new ApplicationUser
                        {
                            UserName = adminEmail,
                            Email = adminEmail,
                            EmailConfirmed = true,
                            FullName = "System Administrator",
                            IsApproved = true, // Admin is auto-approved
                            PhoneNumber = "+1234567890"
                        };

                        var createAdminResult = await userManager.CreateAsync(adminUser, "admin@123");
                        
                        if (createAdminResult.Succeeded)
                        {
                            await userManager.AddToRoleAsync(adminUser, "Admin");
                            logger.LogInformation("Default admin user created successfully.");
                            logger.LogInformation("Admin credentials: admin@gmail.com / admin@123");
                        }
                        else
                        {
                            logger.LogError($"Failed to create admin user: {string.Join(", ", createAdminResult.Errors.Select(e => e.Description))}");
                        }
                    }
                    else
                    {
                        // Ensure admin is approved and has Admin role
                        if (!adminUser.IsApproved)
                        {
                            adminUser.IsApproved = true;
                            await userManager.UpdateAsync(adminUser);
                        }

                        if (!await userManager.IsInRoleAsync(adminUser, "Admin"))
                        {
                            await userManager.AddToRoleAsync(adminUser, "Admin");
                        }
                    }

                    logger.LogInformation("Database seeding completed successfully.");
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "An error occurred while seeding the database.");
                    throw;
                }
            }
        }
    }
}
