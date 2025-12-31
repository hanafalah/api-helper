<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Hanafalah\ApiHelper\Models\PersonalAccessToken;
use Hanafalah\LaravelSupport\Concerns\NowYouSeeMe;

return new class extends Migration
{
    use NowYouSeeMe;

    private $__table;

    public function __construct()
    {
        $this->__table = app(config('database.models.PersonalAccessToken', PersonalAccessToken::class));
    }

    /**
     * Run the migrations.
     */
    public function up(): void
    {
        $table_name = $this->__table->getTable();
        if (!$this->isTableExists()) {
            Schema::create($table_name, function (Blueprint $table) {
                $table->id();
                $table->string('tokenable_type', 50)->nullable(false);
                $table->string('tokenable_id', 36)->nullable(false);
                $table->string('name');
                $table->string('token', 64)->unique();
                $table->text('abilities')->nullable();
                $table->timestamp('last_used_at')->nullable();
                $table->timestamp('expires_at')->nullable();
                $table->string('device_id', 255)->nullable(true);
                $table->json('props')->nullable();
                $table->timestamps();

                $table->index(['tokenable_type', 'tokenable_id'], 'tokenable');
            });
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists($this->__table->getTable());
    }
};
