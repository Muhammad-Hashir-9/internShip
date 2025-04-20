<?php 
session_start(); 
include_once('includes/config.php');

if(isset($_POST['login'])) {
    $password = $_POST['password'];
    $useremail = $_POST['uemail'];
    
    // Validate email format
    if (!filter_var($useremail, FILTER_VALIDATE_EMAIL)) {
        echo "<script>alert('Invalid email format');</script>";
        exit;
    }
    
    // Use prepared statement
    $stmt = $con->prepare("SELECT id, fname, password FROM users WHERE email = ?");
    $stmt->bind_param("s", $useremail);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        
        // Dual verification for transition period
        if(password_verify($password, $user['password']) || $password === $user['password']) {
            // If password was plaintext, hash it and update database
            if($password === $user['password']) {
                $newHash = password_hash($password, PASSWORD_DEFAULT);
                $update = $con->prepare("UPDATE users SET password = ? WHERE id = ?");
                $update->bind_param("si", $newHash, $user['id']);
                $update->execute();
            }
            
            $_SESSION['id'] = $user['id'];
            $_SESSION['name'] = $user['fname'];
            header("location:welcome.php");
            exit;
        }
    }
    
    echo "<script>alert('Invalid username or password');</script>";
}


?>
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8" />
        <meta http-equiv="X-UA-Compatible" content="IE=edge" />
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
        <meta name="description" content="" />
        <meta name="author" content="" />
        <title>User Login | Registration and Login System</title>
        <link href="css/styles.css" rel="stylesheet" />
        <script src="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/js/all.min.js" crossorigin="anonymous"></script>
    </head>
    <body class="bg-primary">
        <div id="layoutAuthentication">
            <div id="layoutAuthentication_content">
                <main>
                    <div class="container">
                        <div class="row justify-content-center">
                            <div class="col-lg-5">
                                <div class="card shadow-lg border-0 rounded-lg mt-5">

<div class="card-header">
<h2 align="center">Registration and Login System</h2>
<hr />
    <h3 class="text-center font-weight-light my-4">User Login</h3></div>
                                    <div class="card-body">
                                        
                                        <form method="post">
                                            
<div class="form-floating mb-3">
<input class="form-control" name="uemail" type="email" placeholder="name@example.com" required/>
<label for="inputEmail">Email address</label>
</div>
                                            

<div class="form-floating mb-3">
<input class="form-control" name="password" type="password" placeholder="Password" required />
<label for="inputPassword">Password</label>
</div>


<div class="d-flex align-items-center justify-content-between mt-4 mb-0">
<a class="small" href="password-recovery.php">Forgot Password?</a>
<button class="btn btn-primary" name="login" type="submit">Login</button>
</div>
</form>
</div>
                                    <div class="card-footer text-center py-3">
                                        <div class="small"><a href="signup.php">Need an account? Sign up!</a></div>
                                          <div class="small"><a href="index.php">Back to Home</a></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </main>
            </div>
<?php include('includes/footer.php');?>
        </div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.0/dist/js/bootstrap.bundle.min.js" crossorigin="anonymous"></script>
        <script src="js/scripts.js"></script>
    </body>
</html>
