package userdata

import (
	"fa-middleware/config"
	"fa-middleware/models"
	"log"
	"time"

	"context"
	"fmt"

	"github.com/FusionAuth/go-client/pkg/fusionauth"
	"github.com/jackc/pgx/v4"
)

func SetUserData(conf config.Config, userData models.UserData) error {
	connStr := fmt.Sprintf(
		"postgres://%v:%v@%v:%v/%v?%v",
		conf.PostgresUser,
		conf.PostgresPass,
		conf.PostgresHost,
		conf.PostgresPort,
		conf.PostgresDBName,
		conf.PostgresOptions,
	)

	// https://github.com/jackc/pgx#example-usage
	conn, err := pgx.Connect(context.Background(), connStr)
	if err != nil {
		return fmt.Errorf("unable to connect to database: %v", err.Error())
	}
	defer conn.Close(context.Background())

	_, err = conn.Exec(
		context.Background(),
		"CREATE TABLE IF NOT EXISTS user_data (user_id VARCHAR ( 36 ), app_id VARCHAR ( 36 ), tenant_id VARCHAR ( 36 ), field VARCHAR ( 128 ), value TEXT, updated_at bigint);",
		// "CREATE TABLE IF NOT EXISTS user_data (user_id VARCHAR ( 36 ) PRIMARY KEY, app_id VARCHAR ( 36 ), tenant_id VARCHAR ( 36 ), field VARCHAR ( 128 ), value TEXT, updated_at DATE NOT NULL DEFAULT CURRENT_DATE);",
	)

	if err != nil {
		return fmt.Errorf("failed to create table: %v", err.Error())
	}

	// TODO: properly use conflict assertion
	// "insert into user_data(user_id, app_id, tenant_id, field, value) values($1, $2, $3, $5, $6) on conflict (user_id, app_id, tenant_id, field) do update set value = EXCLUDED.value",
	// https://www.prisma.io/dataguide/postgresql/inserting-and-modifying-data/insert-on-conflict
	_, err = conn.Exec(
		context.Background(),
		"insert into user_data(user_id, app_id, tenant_id, field, value, updated_at) values($1, $2, $3, $4, $5, $6)",
		userData.UserID,
		userData.AppID,
		userData.TenantID,
		userData.Field,
		userData.Value,
		userData.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to upsert id %v field %v: %v", userData.UserID, userData.Field, err.Error())
	}

	return nil
}

// GetUserData updates the original user data struct with the most recent
// value from the database
func GetUserData(conf config.Config, userData *models.UserData) error {
	connStr := fmt.Sprintf(
		"postgres://%v:%v@%v:%v/%v?%v",
		conf.PostgresUser,
		conf.PostgresPass,
		conf.PostgresHost,
		conf.PostgresPort,
		conf.PostgresDBName,
		conf.PostgresOptions,
	)

	// userDataBytes, err := json.Marshal(userData)
	// if err != nil {
	// 	return fmt.Errorf("failed to marshal user data: %v", err.Error())
	// }

	// https://github.com/jackc/pgx#example-usage
	conn, err := pgx.Connect(context.Background(), connStr)
	if err != nil {
		return fmt.Errorf("unable to connect to database: %v", err.Error())
	}
	defer conn.Close(context.Background())

	// SELECT DISTINCT ON ("field") user_id, app_id, tenant_id, field, value, updated_at FROM "user_data" ORDER BY "field" DESC, "updated_at" DESC

	// better query, but we need to use different data types
	// rows, err := conn.Query(
	// 	context.Background(),
	// 	`SELECT DISTINCT ON ("field") user_id, app_id, tenant_id, field, value, updated_at FROM "user_data" WHERE field LIKE '$1' AND user_id=$2 AND app_id=$3 AND tenant_id=$4 ORDER BY "field" DESC, "updated_at" DESC`,
	// 	userData.Field,
	// 	userData.UserID,
	// 	userData.AppID,
	// 	userData.TenantID,
	// )
	// if err != nil {
	// 	if err == pgx.ErrNoRows {
	// 		return nil
	// 	}
	// 	return fmt.Errorf("failed to query select id %v field %v: %v", userData.UserID, userData.Field, err.Error())
	// }
	// rows.Scan(&)
	// v1 - original query, does not allow for multiple fields to be returned
	err = conn.QueryRow(
		context.Background(),
		"select value from user_data where user_id=$1 and app_id=$2 and tenant_id=$3 and field=$4 order by updated_at desc",
		userData.UserID,
		userData.AppID,
		userData.TenantID,
		userData.Field,
	).Scan(&userData.Value)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil
		}
		return fmt.Errorf("failed to query select id %v field %v: %v", userData.UserID, userData.Field, err.Error())
	}

	return nil
}

func GetValueForUser(conf config.Config, user fusionauth.User, field string) (string, error) {
	userData := models.UserData{
		AppID:    conf.FusionAuthAppID,
		TenantID: conf.FusionAuthTenantID,
		UserID:   user.Id,
		Field:    field,
	}

	err := GetUserData(conf, &userData)
	if err != nil {
		return "", fmt.Errorf(
			"failed to get field %v value for user: %v",
			field,
			err.Error(),
		)
	}

	return userData.Value, nil
}

func GetQueriedFieldsForUser(conf config.Config, user fusionauth.User, field string) (result map[string]string, err error) {
	connStr := fmt.Sprintf(
		"postgres://%v:%v@%v:%v/%v?%v",
		conf.PostgresUser,
		conf.PostgresPass,
		conf.PostgresHost,
		conf.PostgresPort,
		conf.PostgresDBName,
		conf.PostgresOptions,
	)

	result = make(map[string]string)

	// https://github.com/jackc/pgx#example-usage
	conn, err := pgx.Connect(context.Background(), connStr)
	if err != nil {
		return result, fmt.Errorf("unable to connect to database: %v", err.Error())
	}
	defer conn.Close(context.Background())

	// better query, but we need to use different data types
	rows, err := conn.Query(
		context.Background(),
		`SELECT DISTINCT ON ("field") user_id, app_id, tenant_id, field, value, updated_at FROM "user_data" WHERE field LIKE $1 AND user_id=$2 AND app_id=$3 AND tenant_id=$4 ORDER BY "field" DESC, "updated_at" DESC`,
		field,
		user.Id,
		conf.FusionAuthAppID,
		conf.FusionAuthTenantID,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return result, nil
		}
		return result, fmt.Errorf(
			"failed to query select id %v field %v: %v",
			user.Id,
			field,
			err.Error(),
		)
	}
	// TODO: use the proper mechanism for this - this method is unsafe and static
	for {
		if rows.Next() {
			qField := ""
			qValue := ""
			rowBytes := rows.RawValues()
			for f := range rowBytes {
				log.Printf("rowBytes[%v]=%v", f, string(rowBytes[f]))
				switch f {
				case 3: // field as []byte
					qField = string(rowBytes[f])
				case 4: // value as []byte
					qValue = string(rowBytes[f])
				}
			}
			if qField != "" && qValue != "" {
				result[qField] = qValue
			}
		} else {
			break
		}
	}

	return result, nil
}

func SetValueForUser(conf config.Config, user fusionauth.User, field string, value string) error {
	userData := models.UserData{
		AppID:     conf.FusionAuthAppID,
		TenantID:  conf.FusionAuthTenantID,
		UserID:    user.Id,
		Field:     field,
		Value:     value,
		UpdatedAt: time.Now().UnixNano() / 1000000,
	}

	err := SetUserData(conf, userData)
	if err != nil {
		return fmt.Errorf(
			"failed to set field %v value for user: %v",
			field,
			err.Error(),
		)
	}

	return nil
}
