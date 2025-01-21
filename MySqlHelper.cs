
using Microsoft.Extensions.Configuration;
using MySqlConnector;
using System.Data;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using static BR.PC.CertificateIssuanceSystem.Server.SqlGenerator;

namespace SqlHelper;

/// <summary>
/// MySQL数据库操作工具类
/// </summary>
public class MySqlHelper
{
    private static readonly string _database = "lEZM/";  // 加密后的数据库名
    private static readonly string _username = "nzj3c==";       // 加密后的用户名
    private static readonly string _password = "3QNjirJcjmQ==";       // 加密后的密码
    private static readonly string _encryptionKey = "Key123!@#"; // 用于加密解密的密钥
    private static string _connectionString;
    private static readonly object _lock = new object();

    /// <summary>
    /// 获取数据库连接字符串
    /// </summary>
    private static string ConnectionString
    {
        get
        {
            if (string.IsNullOrEmpty(_connectionString))
            {
                lock (_lock)
                {
                    if (string.IsNullOrEmpty(_connectionString))
                    {
                        InitializeConnectionString();
                    }
                }
            }
            return _connectionString;
        }
    }

    /// <summary>
    /// 初始化连接字符串
    /// </summary>
    private static void InitializeConnectionString()
    {
        try
        {
            // 读取配置文件
            IConfiguration configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json")
                .Build();

            string server = configuration["MySqlConfig:Server"];
            int port = int.Parse(configuration["MySqlConfig:Port"]);

            // 解密数据库信息
            string decryptedDatabase = DecryptString(_database);
            string decryptedUsername = DecryptString(_username);
            string decryptedPassword = DecryptString(_password);

            // 构建连接字符串
            _connectionString = $"Server={server};Port={port};Database={decryptedDatabase};Uid={decryptedUsername};Pwd={decryptedPassword};";
        }
        catch (Exception ex)
        {
            throw new Exception("初始化数据库连接字符串失败", ex);
        }
    }

    /// <summary>
    /// 加密字符串
    /// </summary>
    private static string EncryptString(string plainText)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(_encryptionKey.PadRight(32).Substring(0, 32));
            aes.IV = new byte[16];

            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                {
                    swEncrypt.Write(plainText);
                }

                return Convert.ToBase64String(msEncrypt.ToArray());
            }
        }
    }

    /// <summary>
    /// 解密字符串
    /// </summary>
    private static string DecryptString(string cipherText)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(_encryptionKey.PadRight(32).Substring(0, 32));
            aes.IV = new byte[16];

            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(cipherText)))
            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
            {
                return srDecrypt.ReadToEnd();
            }
        }
    }

    /// <summary>
    /// 测试数据库连接是否正常
    /// </summary>
    public static bool TestConnection()
    {
        try
        {
            using (MySqlConnection connection = new MySqlConnection(ConnectionString))
            {
                connection.Open();
                return connection.State == ConnectionState.Open;
            }
        }
        catch (Exception)
        {
            return false;
        }
    }
    public static async Task<int> ExecuteNonQueryAsync(string sql, Dictionary<string, object> parameters)
    {
        using (var connection = new MySqlConnection(ConnectionString))
        {
            await connection.OpenAsync();
            using (var command = new MySqlCommand(sql, connection))
            {
                foreach (var param in parameters)
                {
                    command.Parameters.AddWithValue(param.Key, param.Value);
                }
                return await command.ExecuteNonQueryAsync();
            }
        }
    }
    public static async Task<T> ExecuteScalarAsync<T>(string sql, Dictionary<string, object> parameters)
    {
        using (var connection = new MySqlConnection(ConnectionString))
        {
            await connection.OpenAsync();
            using (var command = new MySqlCommand(sql, connection))
            {
                foreach (var param in parameters)
                {
                    command.Parameters.AddWithValue(param.Key, param.Value);
                }
                var result = await command.ExecuteScalarAsync();
                return (T)Convert.ChangeType(result, typeof(T));
            }
        }
    }

    public static async Task<List<T>> QueryAsync<T>(string sql, Dictionary<string, object> parameters) where T : class, new()
    {
        using (var connection = new MySqlConnection(ConnectionString))
        {
            await connection.OpenAsync();
            using (var command = new MySqlCommand(sql, connection))
            {
                foreach (var param in parameters)
                {
                    command.Parameters.AddWithValue(param.Key, param.Value);
                }

                using (var reader = await command.ExecuteReaderAsync())
                {
                    var results = new List<T>();
                    var properties = typeof(T).GetProperties();

                    // 创建列名到属性的映射
                    var propertyMap = new Dictionary<string, PropertyInfo>(StringComparer.OrdinalIgnoreCase);
                    foreach (var prop in properties)
                    {
                        var columnAttr = prop.GetCustomAttribute<ColumnAttribute>();
                        var columnName = columnAttr?.Name ?? prop.Name;
                        propertyMap[columnName] = prop;
                    }

                    while (await reader.ReadAsync())
                    {
                        var item = new T();
                        for (int i = 0; i < reader.FieldCount; i++)
                        {
                            var columnName = reader.GetName(i);
                            if (propertyMap.TryGetValue(columnName, out PropertyInfo property))
                            {
                                if (!reader.IsDBNull(i))
                                {
                                    var value = reader.GetValue(i);
                                    try
                                    {
                                        // 处理特殊类型转换
                                        if (property.PropertyType == typeof(bool) && value is sbyte)
                                        {
                                            value = Convert.ToBoolean(Convert.ToInt32(value));
                                        }
                                        else if (property.PropertyType.IsEnum)
                                        {
                                            value = Enum.ToObject(property.PropertyType, value);
                                        }
                                        else if (property.PropertyType != value.GetType() && value != DBNull.Value)
                                        {
                                            value = Convert.ChangeType(value, property.PropertyType);
                                        }
                                        property.SetValue(item, value);
                                    }
                                    catch (Exception ex)
                                    {
                                        throw new Exception($"转换属性 {property.Name} 失败，值为 {value}", ex);
                                    }
                                }
                            }
                        }
                        results.Add(item);
                    }
                    return results;
                }
            }
        }
    }
    public static DataTable ExecuteQuery(string sql, Dictionary<string, object> parameters)
    {
        using (MySqlConnection connection = new MySqlConnection(ConnectionString))
        {
            connection.Open();
            using (MySqlTransaction transaction = connection.BeginTransaction())
            {
                try
                {
                    using (MySqlCommand cmd = new MySqlCommand(sql, connection))
                    {
                        cmd.Transaction = transaction;
                        if (parameters != null)
                        {
                            foreach (var param in parameters)
                            {
                                cmd.Parameters.AddWithValue(param.Key, param.Value);
                            }
                        }

                        DataTable dt = new DataTable();
                        using (MySqlDataAdapter adapter = new MySqlDataAdapter(cmd))
                        {
                            adapter.Fill(dt);
                        }

                        transaction.Commit();
                        return dt;
                    }
                }
                catch (Exception)
                {
                    transaction.Rollback();
                    throw;
                }
            }
        }
    }

    /// <summary>
    /// 执行增删改SQL语句
    /// </summary>
    public static int ExecuteNonQuery(string sql, Dictionary<string, object> parameters)
    {
        using (MySqlConnection connection = new MySqlConnection(ConnectionString))
        {
            connection.Open();
            using (MySqlTransaction transaction = connection.BeginTransaction())
            {
                try
                {
                    using (MySqlCommand cmd = new MySqlCommand(sql, connection))
                    {
                        cmd.Transaction = transaction;
                        if (parameters != null)
                        {
                            foreach (var param in parameters)
                            {
                                cmd.Parameters.AddWithValue(param.Key, param.Value);
                            }
                        }

                        int result = cmd.ExecuteNonQuery();
                        transaction.Commit();
                        return result;
                    }
                }
                catch (Exception)
                {
                    transaction.Rollback();
                    throw;
                }
            }
        }
    }

    /// <summary>
    /// 执行查询SQL语句
    /// </summary>
    public static DataTable ExecuteQuery(string sql, params MySqlParameter[] parameters)
    {
        using (MySqlConnection connection = new MySqlConnection(ConnectionString))
        {
            connection.Open();
            using (MySqlTransaction transaction = connection.BeginTransaction())
            {
                try
                {
                    using (MySqlCommand cmd = new MySqlCommand(sql, connection))
                    {
                        cmd.Transaction = transaction;
                        if (parameters != null && parameters.Length > 0)
                        {
                            cmd.Parameters.AddRange(parameters);
                        }

                        DataTable dt = new DataTable();
                        using (MySqlDataAdapter adapter = new MySqlDataAdapter(cmd))
                        {
                            adapter.Fill(dt);
                        }

                        transaction.Commit();
                        return dt;
                    }
                }
                catch (Exception)
                {
                    transaction.Rollback();
                    throw;
                }
            }
        }
    }

    /// <summary>
    /// 执行增删改SQL语句
    /// </summary>
    public static int ExecuteNonQuery(string sql, params MySqlParameter[] parameters)
    {
        using (MySqlConnection connection = new MySqlConnection(ConnectionString))
        {
            connection.Open();
            using (MySqlTransaction transaction = connection.BeginTransaction())
            {
                try
                {
                    using (MySqlCommand cmd = new MySqlCommand(sql, connection))
                    {
                        cmd.Transaction = transaction;
                        if (parameters != null && parameters.Length > 0)
                        {
                            cmd.Parameters.AddRange(parameters);
                        }

                        int result = cmd.ExecuteNonQuery();
                        transaction.Commit();
                        return result;
                    }
                }
                catch (Exception)
                {
                    transaction.Rollback();
                    throw;
                }
            }
        }
    }

    /// <summary>
    /// 用于初始化加密后的配置信息（仅在第一次配置时使用）
    /// </summary>
    public static void InitializeEncryptedConfig(string database, string username, string password)
    {
        Console.WriteLine($"数据库名加密结果: {EncryptString(database)}");
        Console.WriteLine($"用户名加密结果: {EncryptString(username)}");
        Console.WriteLine($"密码加密结果: {EncryptString(password)}");
    }
    /// <summary>
    /// 插入实体
    /// </summary>
    public static async Task<int> InsertAsync<T>(T entity) where T : class
    {
        var (sql, parameters) = GenerateInsertSql(entity);
        return await ExecuteNonQueryAsync(sql, parameters);
    }

    /// <summary>
    /// 更新实体
    /// </summary>
    public static async Task<int> UpdateAsync<T>(T entity, params Condition[] conditions) where T : class
    {
        var (sql, parameters) = GenerateUpdateSql(entity, conditions);
        return await ExecuteNonQueryAsync(sql, parameters);
    }

    /// <summary>
    /// 删除数据
    /// </summary>
    public static async Task<int> DeleteAsync<T>(params Condition[] conditions) where T : class
    {
        var (sql, parameters) = GenerateDeleteSql<T>(conditions);
        return await ExecuteNonQueryAsync(sql, parameters);
    }


}
[AttributeUsage(AttributeTargets.Property)]
public class ColumnAttribute : Attribute
{
    public string Name { get; }
    public ColumnAttribute(string name)
    {
        Name = name;
    }
}
/// <summary>
/// 增强版SQL生成器
/// </summary>
public class SqlGenerator
{
    #region 特性定义
    [AttributeUsage(AttributeTargets.Class)]
    public class TableNameAttribute : Attribute
    {
        public string Name { get; }
        public TableNameAttribute(string name) => Name = name;
    }

    [AttributeUsage(AttributeTargets.Property)]
    public class PrimaryKeyAttribute : Attribute { }

    [AttributeUsage(AttributeTargets.Property)]
    public class IgnoreAttribute : Attribute { }
    #endregion

    #region 查询条件类
    public class Condition
    {
        public string FieldName { get; set; }
        public string Operator { get; set; }
        public object Value { get; set; }
        public string LogicalOperator { get; set; } = "AND";

        public static Condition Equal(string fieldName, object value)
            => new() { FieldName = fieldName, Operator = "=", Value = value };

        public static Condition NotEqual(string fieldName, object value)
            => new() { FieldName = fieldName, Operator = "!=", Value = value };

        public static Condition GreaterThan(string fieldName, object value)
            => new() { FieldName = fieldName, Operator = ">", Value = value };

        public static Condition LessThan(string fieldName, object value)
            => new() { FieldName = fieldName, Operator = "<", Value = value };

        public static Condition Like(string fieldName, string value)
            => new() { FieldName = fieldName, Operator = "LIKE", Value = value };

        public static Condition In(string fieldName, IEnumerable<object> values)
            => new() { FieldName = fieldName, Operator = "IN", Value = values };
    }
    #endregion

    #region 辅助方法
    private static string GetTableName<T>() where T : class
    {
        var type = typeof(T);
        return type.GetCustomAttribute<TableNameAttribute>()?.Name ?? type.Name;
    }

    private static IEnumerable<PropertyInfo> GetValidProperties<T>() where T : class
    {
        return typeof(T).GetProperties()
            .Where(p => p.GetCustomAttribute<IgnoreAttribute>() == null);
    }
    #endregion

    #region SQL生成方法
    /// <summary>
    /// 生成插入SQL
    /// </summary>
    public static (string Sql, Dictionary<string, object> Parameters) GenerateInsertSql<T>(T entity) where T : class
    {
        var parameters = new Dictionary<string, object>();
        var tableName = GetTableName<T>();
        var properties = GetValidProperties<T>();

        var columns = new List<string>();
        var values = new List<string>();
        var paramIndex = 0;

        foreach (var prop in properties)
        {
            var value = prop.GetValue(entity);
            if (value != null)
            {
                columns.Add(prop.Name);
                var paramName = $"@p{paramIndex++}";
                values.Add(paramName);
                parameters.Add(paramName, value);
            }
        }

        var sql = $"INSERT INTO {tableName} ({string.Join(", ", columns)}) VALUES ({string.Join(", ", values)})";
        return (sql, parameters);
    }

    /// <summary>
    /// 生成更新SQL
    /// </summary>
    public static (string Sql, Dictionary<string, object> Parameters) GenerateUpdateSql<T>(
        T entity,
        IEnumerable<Condition> conditions) where T : class
    {
        var parameters = new Dictionary<string, object>();
        var tableName = GetTableName<T>();
        var properties = GetValidProperties<T>();
        var paramIndex = 0;

        var setParts = new List<string>();
        foreach (var prop in properties)
        {
            var value = prop.GetValue(entity);
            if (value != null)
            {
                var paramName = $"@p{paramIndex++}";
                setParts.Add($"{prop.Name} = {paramName}");
                parameters.Add(paramName, value);
            }
        }

        var whereClause = GenerateWhereClause(conditions, ref paramIndex, parameters);
        var sql = $"UPDATE {tableName} SET {string.Join(", ", setParts)} {whereClause}";
        return (sql, parameters);
    }

    /// <summary>
    /// 生成删除SQL
    /// </summary>
    public static (string Sql, Dictionary<string, object> Parameters) GenerateDeleteSql<T>(
        IEnumerable<Condition> conditions) where T : class
    {
        var parameters = new Dictionary<string, object>();
        var tableName = GetTableName<T>();
        var paramIndex = 0;

        var whereClause = GenerateWhereClause(conditions, ref paramIndex, parameters);
        var sql = $"DELETE FROM {tableName} {whereClause}";
        return (sql, parameters);
    }

    /// <summary>
    /// 生成查询SQL
    /// </summary>
    public class QueryBuilder<T> where T : class
    {
        private readonly List<string> _selectedColumns = new();
        private readonly List<Condition> _conditions = new();
        private readonly List<string> _orderBy = new();
        private int? _limit;
        private int? _offset;
        private readonly string _tableName;

        public QueryBuilder()
        {
            _tableName = GetTableName<T>();
        }

        public QueryBuilder<T> Select(params string[] columns)
        {
            _selectedColumns.AddRange(columns);
            return this;
        }

        public QueryBuilder<T> Where(Condition condition)
        {
            _conditions.Add(condition);
            return this;
        }

        public QueryBuilder<T> OrderBy(string column, bool ascending = true)
        {
            _orderBy.Add($"{column} {(ascending ? "ASC" : "DESC")}");
            return this;
        }

        public QueryBuilder<T> Limit(int limit)
        {
            _limit = limit;
            return this;
        }

        public QueryBuilder<T> Offset(int offset)
        {
            _offset = offset;
            return this;
        }

        public (string Sql, Dictionary<string, object> Parameters) Build()
        {
            var parameters = new Dictionary<string, object>();
            var sql = new StringBuilder();
            var paramIndex = 0;

            sql.Append("SELECT ");
            sql.Append(_selectedColumns.Any() ? string.Join(", ", _selectedColumns) : "*");
            sql.Append($" FROM {_tableName}");

            if (_conditions.Any())
            {
                sql.Append(GenerateWhereClause(_conditions, ref paramIndex, parameters));
            }

            if (_orderBy.Any())
            {
                sql.Append(" ORDER BY ").Append(string.Join(", ", _orderBy));
            }

            if (_limit.HasValue)
            {
                sql.Append($" LIMIT {_limit.Value}");
                if (_offset.HasValue)
                {
                    sql.Append($" OFFSET {_offset.Value}");
                }
            }

            return (sql.ToString(), parameters);
        }
    }

    private static string GenerateWhereClause(
        IEnumerable<Condition> conditions,
        ref int paramIndex,
        IDictionary<string, object> parameters)
    {
        if (!conditions?.Any() ?? true) return string.Empty;

        var whereParts = new List<string>();
        foreach (var condition in conditions)
        {
            var paramName = $"@p{paramIndex++}";
            string whereClause;

            if (condition.Operator.Equals("IN", StringComparison.OrdinalIgnoreCase) &&
                condition.Value is IEnumerable<object> values)
            {
                var inParams = new List<string>();
                foreach (var value in values)
                {
                    var inParamName = $"@p{paramIndex++}";
                    inParams.Add(inParamName);
                    parameters.Add(inParamName, value);
                }
                whereClause = $"{condition.FieldName} IN ({string.Join(", ", inParams)})";
            }
            else
            {
                whereClause = $"{condition.FieldName} {condition.Operator} {paramName}";
                parameters.Add(paramName, condition.Value);
            }

            whereParts.Add(whereClause);
        }

        return $" WHERE {string.Join($" {conditions.First().LogicalOperator} ", whereParts)}";
    }
    #endregion
}
[SqlGenerator.TableName("users")]
public class User
{
    [SqlGenerator.PrimaryKey]
    [Column("guid")]
    public Guid Guid { get; set; }
    [Column("userName")]
    public string UserName { get; set; }
    [Column("password")]
    public string Password { get; set; }
    [Column("createTime")]
    public DateTime CreateTime { get; set; }
    [Column("lastModificationTime")]
    public DateTime LastModificationTime { get; set; }
    [Column("status")]
    public UserStatus Status { get; set; }
    [Column("email")]
    public string? Email { get; set; }
    [Column("phoneNumber")]
    public string? PhoneNumber { get; set; }
}

public enum UserStatus
{
    Disable = 0,
    Enable = 1,
    Delete = 2

}
public class UserService
{
    //根据用户名与密码查询以及状态查询用户是否存在
    public static async Task<bool> IsUserExistAsync(string userName, string password, UserStatus status)
    {
        var (query, par) = new SqlGenerator.QueryBuilder<User>()
            .Where(SqlGenerator.Condition.Equal("UserName", userName))
            .Where(SqlGenerator.Condition.Equal("Password", Convert.ToBase64String(MD5.HashData(Encoding.UTF8.GetBytes(password)))))
            .Where(SqlGenerator.Condition.Equal("Status", status))
            .Build();
        return (await MySqlHelper.QueryAsync<User>(query, par)).Count > 0;
    }
    public async Task<bool> InsertOrUpdateUserAsync(string userName, string? password, UserStatus? status, string? email, string? phone)
    {
        if (string.IsNullOrEmpty(userName))
        {
            return false;
        }
        //检查用户名是否存在,如果存在则更新密码或者状态,如果为null标识不更新
        var (query, par) = new SqlGenerator.QueryBuilder<User>()
            .Where(SqlGenerator.Condition.Equal("UserName", userName))
            .Build();
        var user = MySqlHelper.QueryAsync<User>(query, par).Result.FirstOrDefault();
        if (user == null)
        {

            //新添加时string userName, string password, UserStatus status为必须有的如果没有则返回false
            if (string.IsNullOrEmpty(userName) || string.IsNullOrEmpty(password) || status == null)
            {
                return false;
            }
            var cou = await MySqlHelper.InsertAsync<User>(new User() { Guid = Guid.NewGuid(), CreateTime = DateTime.Now, LastModificationTime = DateTime.Now, Password = Convert.ToBase64String(MD5.HashData(Encoding.UTF8.GetBytes(password))), Status = status.Value, UserName = userName, Email = email, PhoneNumber = phone });
            if (cou == 1)
            {
                return true;
            }
        }
        else
        {
            //如果值为null则不更新,直接使用user中的值
            user.LastModificationTime = DateTime.Now;
            if (!string.IsNullOrEmpty(password))
            {
                user.Password = Convert.ToBase64String(MD5.HashData(Encoding.UTF8.GetBytes(password)));
            }
            if (status.HasValue)
            {
                user.Status = status.Value; // 显式转换
            }
            user.Email = email ?? user.Email;
            user.PhoneNumber = phone ?? user.PhoneNumber;

            var cou = await MySqlHelper.UpdateAsync<User>(user);
            if (cou == 1)
            {
                return true;
            }
        }
        return false;
    }
    //根据用户名查询用户信息
    public static async Task<User?> GetUserByUserNameAsync(string userName)
    {
        var (query, par) = new SqlGenerator.QueryBuilder<User>()
            .Where(SqlGenerator.Condition.Equal("UserName", userName))
            .Build();
        return (await MySqlHelper.QueryAsync<User>(query, par)).FirstOrDefault();
    }
    //删除用户
    public static async Task<bool> DeleteUserAsync(string userName)
    {
        var (query, par) = new SqlGenerator.QueryBuilder<User>()
            .Where(SqlGenerator.Condition.Equal("UserName", userName))
            .Build();
        var user = (await MySqlHelper.QueryAsync<User>(query, par)).FirstOrDefault();
        if (user == null)
        {
            return false;
        }
        user.Status = UserStatus.Delete;
        var cou = await MySqlHelper.UpdateAsync(user);
        return cou == 1;
    }
}