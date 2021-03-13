package userdata

import (
	"fa-middleware/config"
	"fa-middleware/models"

	"context"
	"fmt"

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

	_, err = conn.Exec(
		context.Background(),
		"CREATE TABLE IF NOT EXISTS user_data (user_id VARCHAR ( 36 ), app_id VARCHAR ( 36 ), tenant_id VARCHAR ( 36 ), stripe_customer_id VARCHAR ( 18 ), field VARCHAR ( 128 ), value TEXT, updated_at bigint);",
		// "CREATE TABLE IF NOT EXISTS user_data (user_id VARCHAR ( 36 ) PRIMARY KEY, app_id VARCHAR ( 36 ), tenant_id VARCHAR ( 36 ), stripe_customer_id VARCHAR ( 18 ), field VARCHAR ( 128 ), value TEXT, updated_at DATE NOT NULL DEFAULT CURRENT_DATE);",
	)

	if err != nil {
		return fmt.Errorf("failed to create table: %v", err.Error())
	}

	// TODO: set stripe customer ID in a special scenario
	// TODO: properly use conflict assertion
	// "insert into user_data(user_id, app_id, tenant_id, field, value) values($1, $2, $3, $5, $6) on conflict (user_id, app_id, tenant_id, field) do update set value = EXCLUDED.value",
	// https://www.prisma.io/dataguide/postgresql/inserting-and-modifying-data/insert-on-conflict
	_, err = conn.Exec(
		context.Background(),
		"insert into user_data(user_id, app_id, tenant_id, stripe_customer_id, field, value, updated_at) values($1, $2, $3, $4, $5, $6, $7)",
		userData.UserID,
		userData.AppID,
		userData.TenantID,
		userData.StripeCustomerID,
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

	err = conn.QueryRow(
		context.Background(),
		"select value from user_data where user_id=$1 and app_id=$2 and tenant_id=$3 and field=$4 order by updated_at desc",
		userData.UserID,
		userData.AppID,
		userData.TenantID,
		userData.Field,
	).Scan(&userData.Value)
	if err != nil {
		return fmt.Errorf("failed to query select id %v field %v: %v", userData.UserID, userData.Field, err.Error())
	}

	return nil
}
