const emailTemplate = (content) => `
<!DOCTYPE html>
<html>
<head>
  <title>Email from Your Healthcare System</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      margin: 0;
      padding: 20px;
      background-color: #f4f4f4;
    }
    .container {
      background-color: #fff;
      padding: 20px;
      margin: auto;
      width: 80%;
      border: 1px solid #ccc;
      border-radius: 5px;
      box-shadow: 0 0 10px rgba(0,0,0,0.1);
    }
    .header {
      background-color: #007bff;
      color: white;
      text-align: center;
      padding: 10px;
    }
    .footer {
      background-color: #333;
      color: white;
      text-align: center;
      padding: 10px;
    }
  </style>
</head>
<body>

<div class="container">
  <div class="header">
    <h1>X-HMS Solution</h1>
  </div>
  <div class="content">
    ${content}
  </div>
  <div class="footer">
    <p>&copy; ${new Date().getFullYear()} Your Healthcare System. All rights reserved.</p>
  </div>
</div>

</body>
</html>
`;

module.exports = emailTemplate;
