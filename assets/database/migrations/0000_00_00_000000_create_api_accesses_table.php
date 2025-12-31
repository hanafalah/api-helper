<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Hanafalah\ApiHelper\Models\ApiAccess;
use Hanafalah\LaravelSupport\Concerns\NowYouSeeMe;

return new class extends Migration
{
  use NowYouSeeMe;

  private $__table;

  public function __construct()
  {
    $this->__table = app(config('database.models.ApiAccess', ApiAccess::class));
  }

  /**
   * Run the migrations.
   *
   * @return void
   */
  public function up()
  {
    $table_name = $this->__table->getTable();
    if (!$this->isTableExists()) {
      Schema::create($table_name, function (Blueprint $table) {
        $table->ulid('id')->primary();
        $table->mediumInteger('app_code')->unique();
        $table->string('reference_type', 50)->nullable();
        $table->string('reference_id', 36)->nullable();
        $table->text('token')->nullable();
        $table->json('props')->nullable();
        $table->timestamps();
        $table->softDeletes();

        $table->index(['reference_id', 'reference_type'],'api_acc_idx');
      });
    }
  }

  /**
   * Reverse the migrations.
   *
   * @return void
   */
  public function down()
  {
    Schema::dropIfExists($this->__table->getTable());
  }
};
